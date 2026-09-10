//! Dynamically provisions TLS certificates

use std::{cmp::min, ops::Range};

use async_trait::async_trait;
use chrono::{FixedOffset, TimeZone};
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    conf::{Conf, ConfMethod},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        X509Builder, X509NameBuilder,
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
    },
};
use rand::Rng;
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use stackable_operator::{kube::runtime::reflector::ObjectRef, shared::time::Duration};
use time::OffsetDateTime;

use crate::{
    backend::{
        ProvisionParts, ScopeAddressesError, SecretBackend, SecretBackendError, SecretContents,
        SecretVolumeSelector,
        pod_info::{Address, PodInfo},
        scope::SecretScope,
    },
    crd::v1alpha2,
    format::{SecretData, WellKnownSecretData, well_known},
    utils::iterator_try_concat_bytes,
};

mod ca;

/// Fraction of the active lifetime of a CA after which it is rotated.
// Use a fraction instead of a factor because [`Duration::mul`] is not defined for floating point
// numbers.
pub const CA_ROTATION_FRACTION: u32 = 2;

/// How long CA certificates should last for. Also used for calculating when they should be rotated.
pub const DEFAULT_CA_CERT_LIFETIME: Duration = Duration::from_days_unchecked(365);

/// Duration at the end of the CA certificate lifetime where no certificates signed by the CA
/// certificate may exist.
///
/// The CA certificate is not published anymore while in retirement to avoid that pods get almost
/// expired certificates.
///
/// see <https://github.com/stackabletech/secret-operator/issues/625>
pub const DEFAULT_CA_CERT_RETIREMENT_DURATION: Duration = Duration::from_hours_unchecked(1);

/// As the Pods will be evicted [`DEFAULT_CERT_RESTART_BUFFER`] before
/// the cert actually expires, this results in a restart in approx every 2 weeks,
/// which matches the rolling re-deploy of k8s nodes of e.g.:
/// * 1 week for IONOS
/// * 2 weeks for some on-prem k8s clusters
///
/// [`DEFAULT_MAX_CERT_LIFETIME`] must be less than `([DEFAULT_CA_CERT_LIFETIME] -
/// [DEFAULT_CA_CERT_RETIREMENT_DURATION]) / [CA_ROTATION_FACTOR] / 2`.
///
/// see the explanation in [`v1alpha2::AutoTlsBackend::max_certificate_lifetime`]
pub const DEFAULT_MAX_CERT_LIFETIME: Duration = Duration::from_days_unchecked(15);

/// Default lifetime of certs when no annotations are set on the Volume.
pub const DEFAULT_CERT_LIFETIME: Duration = Duration::from_hours_unchecked(24);

/// When a StatefulSet has many Pods (e.g. 80 HDFS datanodes or Trino workers) a rolling
/// redeployment can take multiple hours. When the certificates of all datanodes
/// expire approximately at the same time, only a certain number of Pods can be unavailable.
/// So they need to be restarted sequentially - combined with a graceful shutdown this can
/// take hours. To prevent expired certificates we need to evict them enough time in advance
/// - which is the purpose of the buffer.
pub const DEFAULT_CERT_RESTART_BUFFER: Duration = Duration::from_hours_unchecked(6);

/// We randomize the certificate lifetimes slightly, in order to avoid all pods of a set restarting/failing at the same time.
pub const DEFAULT_CERT_JITTER_FACTOR: f64 = 0.2;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to get addresses for scope {:?}", format!("{scope}")))]
    ScopeAddresses {
        source: ScopeAddressesError,
        scope: SecretScope,
    },

    #[snafu(display("failed to generate certificate key"))]
    GenerateKey { source: openssl::error::ErrorStack },

    #[snafu(display("failed to load CA"))]
    LoadCa { source: ca::Error },

    #[snafu(display("failed to pick a CA"))]
    PickCa { source: ca::GetCaError },

    #[snafu(display("failed to build certificate"))]
    BuildCertificate { source: openssl::error::ErrorStack },

    #[snafu(display("failed to serialize {tpe:?} certificate"))]
    SerializeCertificate {
        source: openssl::error::ErrorStack,
        tpe: CertType,
    },

    #[snafu(display("invalid certificate lifetime"))]
    InvalidCertLifetime { source: DateTimeOutOfBoundsError },

    #[snafu(display("retirement duration is not shorter than the CA certificate lifetime"))]
    RetirementDurationNotShorterThanCertificateLifetime {
        ca_certificate_lifetime: Duration,
        ca_certificate_retirement_duration: Duration,
    },

    #[snafu(display(
        "certificate expiring at {expires_at} would schedule the pod to be restarted at {restart_at}, which is in the past (and we don't have a time machine (yet and/or anymore))"
    ))]
    TooShortCertLifetimeRequiresTimeTravel {
        expires_at: OffsetDateTime,
        restart_at: OffsetDateTime,
    },

    #[snafu(display("invalid jitter factor {requested} requested, must be within {range:?}"))]
    JitterOutOfRange { requested: f64, range: Range<f64> },
}
type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum CertType {
    Ca,
    Pod,
}

impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::ScopeAddresses { .. } => tonic::Code::Unavailable,
            Error::GenerateKey { .. } => tonic::Code::Internal,
            Error::LoadCa { source } => source.grpc_code(),
            Error::PickCa { source } => source.grpc_code(),
            Error::BuildCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SerializeCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::InvalidCertLifetime { .. } => tonic::Code::Internal,
            Error::RetirementDurationNotShorterThanCertificateLifetime { .. } => {
                tonic::Code::InvalidArgument
            }
            Error::TooShortCertLifetimeRequiresTimeTravel { .. } => tonic::Code::InvalidArgument,
            Error::JitterOutOfRange { .. } => tonic::Code::InvalidArgument,
        }
    }

    fn secondary_object(&self) -> Option<ObjectRef<stackable_operator::kube::api::DynamicObject>> {
        match self {
            Error::ScopeAddresses { source, .. } => source.secondary_object(),
            Error::GenerateKey { .. } => None,
            Error::LoadCa { source } => source.secondary_object(),
            Error::PickCa { source } => source.secondary_object(),
            Error::BuildCertificate { .. } => None,
            Error::SerializeCertificate { .. } => None,
            Error::InvalidCertLifetime { .. } => None,
            Error::RetirementDurationNotShorterThanCertificateLifetime { .. } => None,
            Error::TooShortCertLifetimeRequiresTimeTravel { .. } => None,
            Error::JitterOutOfRange { .. } => None,
        }
    }
}

/// How long before its certificate expires a CA is replaced by a freshly provisioned one.
///
/// This is the rotation cadence the operator runs on: it is passed to
/// `ca::Manager::load_or_create` as `rotate_if_ca_expires_before`, and the safe leaf-certificate
/// clamp below is derived from it (exactly half of it). Keeping it in one function means the
/// production reconcile path and the property tests that model rotation share a single definition
/// and cannot drift apart.
fn ca_rotation_threshold(
    ca_certificate_lifetime: Duration,
    ca_certificate_retirement_duration: Duration,
) -> Duration {
    let active_ca_certificate_lifetime =
        ca_certificate_lifetime - ca_certificate_retirement_duration;
    active_ca_certificate_lifetime / CA_ROTATION_FRACTION
}

/// The largest leaf-certificate lifetime that is safe to hand out, given a CA that is rotated
/// every `active_ca_certificate_lifetime / CA_ROTATION_FRACTION`.
///
/// The goal is that two pods whose certificate validity windows overlap always trust each
/// other's issuer. If a leaf may live too long, a pod that mounted just before a CA rotation
/// (and therefore only trusts the old CA) can overlap a pod signed by the new CA, and mTLS
/// between them breaks.
///
/// # Derivation
///
/// Let `L` = `ca_certificate_lifetime`, `R` = `ca_certificate_retirement_duration`,
/// `A = L - R` (the active lifetime), and `F` = `CA_ROTATION_FRACTION`. A CA born at `t`
/// expires at `t + L`, but is retired `R` earlier, so its usable-until cutoff (for both
/// anchoring trust and signing leaves) is `u = t + A`. Replacement CAs are spaced
/// `P = L - A/F` apart. Placing the new CA's birth at `t = 0`, the previous CA's usable-until
/// is `u0 = A - P = A/F - R`.
///
/// Take the worst case: pod 1 mounts just before the rotation (so it does not know the new
/// CA) and lives until `max_leaf`; pod 2 mounts at `m2 >= 0` and is forced onto the new CA once
/// the old one can no longer cover its leaf, i.e. `m2 > u0 - max_leaf`. Their windows overlap
/// while `m2 < max_leaf`, so a trust gap exists iff `u0 - max_leaf < max_leaf`, i.e.
/// `max_leaf > u0 / 2`. The invariant therefore holds iff:
///
/// ```text
/// max_leaf <= u0 / 2 = A/(2F) - R/2
/// ```
///
/// With `F = 2` that is `(L - 3R)/4`.
///
/// # Known gap (this is why the invariant tests below currently fail)
///
/// The formula this function actually returns is `A/(2F) = (L - R)/4`, which omits the
/// `- R/2` term above, so it overshoots the safe bound by exactly `R/2`, for any `F`. The
/// original overlap argument predates the retirement duration and subtracts `R` only once
/// (to form `A`), whereas the geometry needs it subtracted at the trust cutoff too. With the
/// defaults (`R = 1h`, `L = 365d`) the gap is negligible, but a config such as `L = 100d,
/// R = 30d` is accepted (production only enforces `R < L`) and can still hit the
/// `NoCaLivesLongEnough` mount error near a rotation boundary. `overlapping_pods_mutually_trust`
/// demonstrates this; the fix is to return `(L - 3R)/4` and validate `L > 3R`.
///
/// The necessity of `(L - 3R)/4` is proven by the argument above; its *sufficiency* across the
/// full config domain is currently only established empirically, by the property test.
///
/// The returned value is left unchanged on purpose (it is still the known-too-loose `active/F/2`);
/// this change set only adds the tests that expose the gap, so a follow-up fix can be validated
/// against them.
fn safe_max_cert_lifetime(
    ca_certificate_lifetime: Duration,
    ca_certificate_retirement_duration: Duration,
) -> Duration {
    // The safe clamp is exactly half the rotation cadence; see `ca_rotation_threshold`.
    ca_rotation_threshold(ca_certificate_lifetime, ca_certificate_retirement_duration) / 2
}

#[derive(Debug)]
pub struct TlsGenerate {
    ca_manager: ca::Manager,
    max_cert_lifetime: Duration,
    key_generation: v1alpha2::CertificateKeyGeneration,
}

impl TlsGenerate {
    /// Check if a signing CA has already been instantiated in a specified Kubernetes secret - if
    /// one is found the key is loaded and used for signing certs.
    /// If no current authority can be found, a new key pair and self signed certificate is created
    /// and stored for future use.
    /// This allows users to provide their own CA files, but also enables secret-operator to generate
    /// an independent self-signed CA.
    pub async fn get_or_create_k8s_certificate(
        client: &stackable_operator::client::Client,
        v1alpha2::AutoTlsCa {
            secret: ca_secret,
            auto_generate: auto_generate_ca,
            ca_certificate_lifetime,
            ca_certificate_retirement_duration,
            key_generation,
        }: &v1alpha2::AutoTlsCa,
        additional_trust_roots: &[v1alpha2::AdditionalTrustRoot],
        max_cert_lifetime: Duration,
    ) -> Result<Self> {
        ensure!(
            ca_certificate_retirement_duration < ca_certificate_lifetime,
            RetirementDurationNotShorterThanCertificateLifetimeSnafu {
                ca_certificate_lifetime: *ca_certificate_lifetime,
                ca_certificate_retirement_duration: *ca_certificate_retirement_duration
            }
        );

        let safe_max_cert_lifetime =
            safe_max_cert_lifetime(*ca_certificate_lifetime, *ca_certificate_retirement_duration);

        if max_cert_lifetime > safe_max_cert_lifetime {
            tracing::warn!(%max_cert_lifetime, %safe_max_cert_lifetime, "maxCertificateLifetime is longer than (caCertificateLifetime - caCertificateRetirementDuration) / {} and will be capped", CA_ROTATION_FRACTION * 2);
        }

        let max_cert_lifetime = min(max_cert_lifetime, safe_max_cert_lifetime);

        Ok(Self {
            ca_manager: ca::Manager::load_or_create(
                client,
                ca_secret,
                additional_trust_roots,
                &ca::Config {
                    manage_ca: *auto_generate_ca,
                    ca_certificate_lifetime: *ca_certificate_lifetime,
                    ca_certificate_retirement_duration: *ca_certificate_retirement_duration,
                    rotate_if_ca_expires_before: Some(ca_rotation_threshold(
                        *ca_certificate_lifetime,
                        *ca_certificate_retirement_duration,
                    )),
                    key_generation: key_generation.clone(),
                },
            )
            .await
            .context(LoadCaSnafu)?,
            max_cert_lifetime,
            key_generation: key_generation.clone(),
        })
    }
}

#[async_trait]
impl SecretBackend for TlsGenerate {
    type Error = Error;

    /// Generate a key pair and sign it with the CA key.
    /// Then add the ca certificate and return these files for provisioning to the volume.
    async fn get_secret_data(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<SecretContents, Self::Error> {
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::from_minutes_unchecked(5);

        // Extract and convert consumer input from the Volume annotations.
        let cert_lifetime = selector.autotls_cert_lifetime;
        let cert_restart_buffer = selector.autotls_cert_restart_buffer;

        // We need to check that the cert lifetime it is not longer than allowed,
        // by capping it to the maximum configured at the SecretClass.
        let cert_lifetime = if cert_lifetime > self.max_cert_lifetime {
            tracing::info!(
                certificate.lifetime.requested = %cert_lifetime,
                certificate.lifetime.maximum = %self.max_cert_lifetime,
                certificate.lifetime = %self.max_cert_lifetime,
                "Pod requested a certificate to have a longer lifetime than the configured maximum, reducing",
            );
            self.max_cert_lifetime
        } else {
            cert_lifetime
        };

        // Jitter the certificate lifetimes
        let jitter_factor_cap = selector.autotls_cert_jitter_factor;
        let jitter_factor_allowed_range = 0.0..1.0;
        if !jitter_factor_allowed_range.contains(&jitter_factor_cap) {
            return JitterOutOfRangeSnafu {
                requested: jitter_factor_cap,
                range: jitter_factor_allowed_range,
            }
            .fail();
        }
        let jitter_factor = rand::rng().random_range(0.0..jitter_factor_cap);
        let jitter_amount = Duration::from(cert_lifetime.mul_f64(jitter_factor));
        let unjittered_cert_lifetime = cert_lifetime;
        let cert_lifetime = cert_lifetime - jitter_amount;

        tracing::info!(
            certificate.lifetime.requested = %unjittered_cert_lifetime,
            certificate.lifetime.jitter = %jitter_amount,
            certificate.lifetime.jitter.factor = jitter_factor,
            certificate.lifetime.jitter.factor.cap = jitter_factor_cap,
            certificate.lifetime = %cert_lifetime,
            "Applying jitter to certificate lifetime",
        );

        let not_after = now + cert_lifetime;
        let expire_pod_after = not_after - cert_restart_buffer;
        if expire_pod_after <= now {
            TooShortCertLifetimeRequiresTimeTravelSnafu {
                expires_at: not_after,
                restart_at: expire_pod_after,
            }
            .fail()?;
        }

        let ca = self
            .ca_manager
            .find_certificate_authority_for_signing(not_after)
            .context(PickCaSnafu)?;

        // Only run leaf certificate generation if it was requested based on the
        // secret volume selector. Otherwise only a ca.crt file as a PEM envelope
        // will be available (to be mounted).
        let (certificate_pem, key_pem) = match selector.provision_parts {
            ProvisionParts::Public => (None, None),
            ProvisionParts::PublicPrivate => {
                let conf = Conf::new(ConfMethod::default())
                    .expect("failed to initialize OpenSSL configuration");

                let pod_key_length = match self.key_generation {
                    v1alpha2::CertificateKeyGeneration::Rsa { length } => length,
                };

                let pod_key = Rsa::generate(pod_key_length)
                    .and_then(PKey::try_from)
                    .context(GenerateKeySnafu)?;

                let mut addresses = Vec::new();
                for scope in &selector.scope {
                    addresses.extend(
                        selector
                            .scope_addresses(&pod_info, scope)
                            .context(ScopeAddressesSnafu { scope })?,
                    );
                }
                for address in &mut addresses {
                    if let Address::Dns(dns) = address {
                        // Turn FQDNs into bare domain names by removing the trailing dot
                        if dns.ends_with('.') {
                            dns.pop();
                        }
                    }
                }

                let domain_components = if selector.autotls_cert_domain_components_in_subject_dn {
                    [
                        Some(pod_info.pod_name.as_str()),
                        pod_info.service_name.as_deref(),
                        Some(&pod_info.namespace),
                        Some("svc"),
                    ]
                    .into_iter()
                    .flatten()
                    .chain(pod_info.kubernetes_cluster_domain.split('.'))
                    .collect()
                } else {
                    vec![]
                };

                let pod_cert = X509Builder::new()
                    .and_then(|mut x509| {
                        let subject_name = X509NameBuilder::new()
                            .and_then(|mut name| {
                                name.append_entry_by_nid(
                                    Nid::COMMONNAME,
                                    "generated certificate for pod",
                                )?;
                                for domain_component in domain_components {
                                    name.append_entry_by_nid(
                                        Nid::DOMAINCOMPONENT,
                                        domain_component,
                                    )?;
                                }
                                Ok(name)
                            })?
                            .build();
                        x509.set_subject_name(&subject_name)?;
                        x509.set_issuer_name(ca.certificate.subject_name())?;
                        x509.set_not_before(
                            Asn1Time::from_unix(not_before.unix_timestamp())?.as_ref(),
                        )?;
                        x509.set_not_after(
                            Asn1Time::from_unix(not_after.unix_timestamp())?.as_ref(),
                        )?;
                        x509.set_pubkey(&pod_key)?;
                        x509.set_version(
                            3 - 1, // zero-indexed
                        )?;
                        let mut serial = BigNum::new()?;
                        serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
                        x509.set_serial_number(Asn1Integer::from_bn(&serial)?.as_ref())?;
                        let ctx = x509.x509v3_context(Some(&ca.certificate), Some(&conf));
                        let mut exts = vec![
                            BasicConstraints::new().critical().build()?,
                            KeyUsage::new()
                                .key_encipherment()
                                .digital_signature()
                                .build()?,
                            ExtendedKeyUsage::new()
                                .server_auth()
                                .client_auth()
                                .build()?,
                            SubjectKeyIdentifier::new().build(&ctx)?,
                            AuthorityKeyIdentifier::new()
                                .issuer(true)
                                .keyid(true)
                                .build(&ctx)?,
                        ];
                        let mut san_ext = SubjectAlternativeName::new();
                        san_ext.critical();
                        let mut has_san = false;
                        for addr in addresses {
                            has_san = true;
                            match addr {
                                Address::Dns(dns) => san_ext.dns(&dns),
                                Address::Ip(ip) => san_ext.ip(&ip.to_string()),
                            };
                        }
                        if has_san {
                            exts.push(san_ext.build(&ctx)?);
                        }
                        for ext in exts {
                            x509.append_extension(ext)?;
                        }
                        x509.sign(&ca.private_key, MessageDigest::sha256())?;
                        Ok(x509)
                    })
                    .context(BuildCertificateSnafu)?
                    .build();

                let certificate_pem = pod_cert
                    .to_pem()
                    .context(SerializeCertificateSnafu { tpe: CertType::Pod })?;
                let key_pem = pod_key
                    .private_key_to_pem_pkcs8()
                    .context(SerializeCertificateSnafu { tpe: CertType::Pod })?;

                (Some(certificate_pem), Some(key_pem))
            }
        };

        let ca_pem =
            iterator_try_concat_bytes(self.ca_manager.trust_roots(now).into_iter().map(|ca| {
                ca.to_pem()
                    .context(SerializeCertificateSnafu { tpe: CertType::Ca })
            }))?;

        Ok(
            SecretContents::new(SecretData::WellKnown(WellKnownSecretData::TlsPem(
                well_known::TlsPem {
                    certificate_pem,
                    key_pem,
                    ca_pem,
                },
            )))
            .expires_after(
                time_datetime_to_chrono(expire_pod_after).context(InvalidCertLifetimeSnafu)?,
            ),
        )
    }

    async fn get_trust_data(
        &self,
        _selector: &super::TrustSelector,
    ) -> Result<SecretContents, Self::Error> {
        let now = OffsetDateTime::now_utc();
        let active_trust_roots = self.ca_manager.trust_roots(now);
        let pems = active_trust_roots.into_iter().map(|ca| {
            ca.to_pem()
                .context(SerializeCertificateSnafu { tpe: CertType::Ca })
        });
        let concatenated_pem = iterator_try_concat_bytes(pems)?;

        Ok(SecretContents::new(SecretData::WellKnown(
            WellKnownSecretData::TlsPem(well_known::TlsPem {
                ca_pem: concatenated_pem,
                certificate_pem: None,
                key_pem: None,
            }),
        )))
    }
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum DateTimeOutOfBoundsError {
    #[snafu(display("datetime is invalid"))]
    DateTime,

    #[snafu(display("time zone is out of bounds"))]
    TimeZone,
}
fn time_datetime_to_chrono(
    dt: time::OffsetDateTime,
) -> Result<chrono::DateTime<FixedOffset>, DateTimeOutOfBoundsError> {
    let tz = chrono::FixedOffset::east_opt(dt.offset().whole_seconds())
        .context(date_time_out_of_bounds_error::TimeZoneSnafu)?;
    tz.timestamp_opt(dt.unix_timestamp(), dt.nanosecond())
        .earliest()
        .context(date_time_out_of_bounds_error::DateTimeSnafu)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use stackable_operator::shared::time::Duration;
    use time::format_description::well_known::Rfc3339;

    use super::{ca_rotation_threshold, safe_max_cert_lifetime, time_datetime_to_chrono};

    fn secs(duration: Duration) -> i64 {
        duration.as_secs() as i64
    }

    fn dur(seconds: i64) -> Duration {
        Duration::from(std::time::Duration::from_secs(seconds.max(0) as u64))
    }

    // Property: for any accepted SecretClass config, a pod requesting a certificate should never be
    // told "no CA lives long enough" (the `NoCaLivesLongEnough` / `FailedPrecondition` mount error).
    //
    // This models the whole steady-state lifecycle in plain integer seconds:
    //   * the real `safe_max_cert_lifetime` clamp is called (not re-implemented),
    //   * CA rotation mirrors `ca::Manager::load_or_create` (new CA once the newest one expires
    //     within `active/CA_ROTATION_FRACTION`),
    //   * the signing check mirrors `active_certificate_authorities`
    //     (`ca.not_after - retirement >= leaf.not_after`).
    //
    // Modeling assumptions:
    //   * rotation is evaluated on every request (true today: every NodePublishVolume rebuilds the
    //     backend via `from_class` -> `load_or_create`).
    //   * worst case leaf lifetime = the clamped maximum (jitter only ever *shortens* it, which
    //     makes signing strictly easier, so it cannot cause this failure).
    //
    // This asserts the true invariant against the real, shipped `safe_max_cert_lifetime` over the
    // whole space of *accepted* configs (production only enforces `retirement < caLifetime`). It is
    // EXPECTED TO FAIL on the current code: the clamp of `active/4` is only sufficient when
    // `active/4 <= active/2 - retirement`, i.e. `caLifetime >= ~5 * retirement`. Configs with a
    // larger retirement (e.g. L=100d, R=30d) are accepted but still hit the exact `NoCaLivesLongEnough`
    // mount error near a rotation boundary; proptest shrinks to something like
    // `ca_lifetime=3600, retirement=788, max_leaf_lifetime=638`.
    // Defaults (R=1h, L=365d) are far inside the safe region. Fix: clamp to
    // `(caLifetime - 3*retirement)/4` (and validate `L > 3R`), after which this test passes.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn signing_ca_always_available(
            // caCertificateLifetime, in whole seconds. The range spans 1 hour (a deliberately tiny
            // value, as used in tests and fast-rotation setups) up to 400 days, comfortably past
            // the 365-day default, so both very short-lived and long-lived CAs are covered.
            ca_lifetime in 3600i64..=400 * 86400,
            // caCertificateRetirementDuration, drawn as a per-mille fraction (1..=999) of the CA
            // lifetime rather than as an absolute duration. This matters for coverage:
            //   * production's only rule is `retirement < caLifetime`; a fraction below 1000 is
            //     always inside that accepted domain, whatever the lifetime, so no generated case
            //     is thrown away as a rejected config.
            //   * it sweeps the whole ratio, including the large retirements (tens of percent of
            //     the lifetime) where the shipped clamp is wrong. A fixed absolute range would,
            //     against a multi-day lifetime, almost always be a rounding-error fraction and
            //     never reach the failing region.
            retirement_permille in 1i64..=999,
            // maxCertificateLifetime requested by the SecretClass. Runs up to 3x the largest CA
            // lifetime so the request straddles the clamp: for some cases it exceeds the clamp
            // (which then caps the leaf), for others it sits below it (clamp is a no-op). The
            // invariant has to hold on both sides.
            requested_max_lifetime in 1i64..=3 * 400 * 86400,
        ) {
            let retirement = (ca_lifetime * retirement_permille / 1000).max(1);
            prop_assume!(retirement < ca_lifetime);

            // The real production clamp, applied just as `get_or_create_k8s_certificate` does.
            let clamped_max = secs(safe_max_cert_lifetime(dur(ca_lifetime), dur(retirement)));
            let max_leaf_lifetime = requested_max_lifetime.min(clamped_max);
            prop_assume!(max_leaf_lifetime > 0);

            // Rotation threshold, from the real production function so it cannot drift.
            let rotate_before = secs(ca_rotation_threshold(dur(ca_lifetime), dur(retirement)));

            // Simulate three CA-lifetimes (enough for at least two rotations), sampling 16 ticks
            // per rotation window.
            let simulation_horizon = 3 * ca_lifetime;
            let time_step = (rotate_before / 16).max(1);

            // CA set, represented by each CA's `not_after`. Bootstrap CA created at t=0.
            let mut cas = vec![ca_lifetime];
            let mut now = 0i64;
            while now <= simulation_horizon {
                cas.retain(|&not_after| not_after >= now); // drop fully-expired CAs

                // Rotation (mirrors load_or_create): provision a fresh CA if the newest expires soon.
                let newest_not_after = *cas.iter().max().unwrap();
                if newest_not_after < now + rotate_before {
                    cas.push(now + ca_lifetime);
                }

                // Signing (mirrors find_certificate_authority_for_signing): does *any* CA outlive
                // the leaf, accounting for retirement?
                let leaf_not_after = now + max_leaf_lifetime;
                let signable = cas
                    .iter()
                    .any(|&not_after| not_after - retirement >= leaf_not_after);
                prop_assert!(
                    signable,
                    "no CA can sign at now={now}: leaf_not_after={leaf_not_after}, cas={cas:?} \
                     (ca_lifetime={ca_lifetime}, retirement={retirement}, \
                     requested_max_lifetime={requested_max_lifetime}, clamped_max={clamped_max}, \
                     max_leaf_lifetime={max_leaf_lifetime})",
                );

                now += time_step;
            }
        }
    }

    // One pod's view of the world at the instant it mounted its secret.
    #[derive(Clone, Debug)]
    struct Pod {
        start: i64,
        end: i64,
        signer: usize,     // id of the CA that signed this pod's leaf cert
        trust: Vec<usize>, // ids of the CAs in this pod's (frozen-at-mount) trust store
    }

    // A Certificate Authority as it exists during the simulation: a unique `id` plus the
    // wall-clock second at which its certificate expires (`not_after`).
    #[derive(Clone, Copy, Debug)]
    struct Ca {
        id: usize,
        not_after: i64,
    }

    impl Ca {
        // Can this CA vouch for something that must stay valid until `deadline`?
        //
        // A CA is pulled out of service `retirement` seconds before its certificate actually
        // expires, so the usable cutoff is `not_after - retirement`, not `not_after`. This single
        // predicate is the shared core of both real functions:
        //   * `trust_roots(now)`                       -> `covers(now, retirement)`      (trust anchor)
        //   * `find_certificate_authority_for_signing` -> `covers(leaf_end, retirement)` (can sign)
        fn covers(&self, deadline: i64, retirement: i64) -> bool {
            self.not_after - retirement >= deadline
        }
    }

    // Simulate the CA lifecycle and record one pod mounted at every reconcile tick, exactly as
    // `get_secret_data` would: the signer is the oldest CA that outlives the leaf, and the trust
    // store is `trust_roots(now)`, both frozen for the pod's whole life.
    fn simulate_pods(ca_lifetime: i64, retirement: i64, max_leaf_lifetime: i64) -> Vec<Pod> {
        // Provision a replacement CA once the longest-lived CA is within `rotate_before` of
        // expiring. Calls the real `ca_rotation_threshold`, so the simulated cadence and the
        // production cadence share one definition and cannot drift.
        let rotate_before = secs(ca_rotation_threshold(dur(ca_lifetime), dur(retirement)));

        // Simulate three CA-lifetimes. That is long enough to see at least two rotations,
        // and cross-pod trust gaps only ever appear *across* a rotation. Sample 16 ticks per
        // rotation window: fine enough to land a pod exactly on a rotation boundary (where the
        // gap opens), coarse enough that the test stays fast.
        let simulation_horizon = 3 * ca_lifetime;
        let time_step = (rotate_before / 16).max(1);

        // The set of CAs that exist right now. Bootstrap with a single CA (id 0), created at
        // t=0 and valid for one full lifetime.
        let mut cas = vec![Ca { id: 0, not_after: ca_lifetime }];
        let mut next_id = 1usize;

        let mut pods = Vec::new();

        // Walk simulated time forward one tick at a time. Each iteration models a single
        // reconcile at instant `now`, exactly what happens when a pod mounts its secret and
        // `get_secret_data` runs (rotation is re-evaluated on *every* mount, so doing it here
        // in the loop is faithful).
        let mut now = 0i64;
        while now <= simulation_horizon {
            // (1) Forget CAs whose certificates have fully expired. They no longer exist.
            cas.retain(|ca| ca.not_after >= now);

            // (2) Rotation. If even the longest-lived CA expires within `rotate_before`,
            //     provision a fresh CA valid for a full lifetime. Repeated over three lifetimes
            //     this produces a rolling, overlapping series of CAs rather than a single one.
            let newest_not_after = cas.iter().map(|ca| ca.not_after).max().unwrap();
            if newest_not_after < now + rotate_before {
                cas.push(Ca { id: next_id, not_after: now + ca_lifetime });
                next_id += 1;
            }

            // (3) The trust store this pod mounts with = `trust_roots(now)`: every CA that is
            //     still a valid anchor at `now`. Crucially the real operator freezes this set
            //     into the pod and never refreshes it until the pod restarts, so we snapshot
            //     it here and store it on the Pod.
            let trust: Vec<usize> = cas
                .iter()
                .filter(|ca| ca.covers(now, retirement))
                .map(|ca| ca.id)
                .collect();

            // (4) The CA that signs this pod's leaf. The leaf must stay valid until
            //     `leaf_not_after`, so a CA qualifies only if it `covers` that deadline. Among
            //     the qualifying CAs we pick the OLDEST one: it is trusted by the most existing
            //     peers, so it maximizes connectivity. This mirrors
            //     `find_certificate_authority_for_signing`. `None` means no CA can sign at all.
            //     That failure is the job of `signing_ca_always_available`, so we skip the pod
            //     here and only reason about pods that actually mounted.
            let leaf_not_after = now + max_leaf_lifetime;
            let signer = cas
                .iter()
                .filter(|ca| ca.covers(leaf_not_after, retirement))
                .min_by_key(|ca| ca.not_after)
                .map(|ca| ca.id);

            // (5) Record the pod. Its validity window [start, end], its signer, and its trust
            //     set are all fixed for the pod's entire life. That immutability is what the
            //     overlap invariant later checks against.
            if let Some(signer) = signer {
                pods.push(Pod {
                    start: now,
                    end: leaf_not_after,
                    signer,
                    trust,
                });
            }

            now += time_step;
        }
        pods
    }

    // Invariant: if two pods' certificate validity windows overlap, they must mutually trust each
    // other, otherwise mTLS between them breaks during a CA rotation.
    //
    // Asserted against the real, shipped `safe_max_cert_lifetime` over the whole accepted-config
    // space. It is EXPECTED TO FAIL on the current code: this invariant needs
    // `max_leaf <= active/4 - retirement/2 = (caLifetime - 3*retirement)/4`, but the shipped clamp
    // is `active/4`, too loose by `retirement/2` (the `/4` overlap argument predates the retirement
    // feature). Defaults (R=1h, L=365d, max=15d << clamp) are far inside the safe region. Fix:
    // clamp to `(caLifetime - 3*retirement)/4` (and validate `L > 3R`), after which this test passes.
    //
    // Worked example (caLifetime=100d, retirement=30d, accepted since retirement < caLifetime):
    //
    // How the code turns that config into numbers:
    //   * active lifetime         = caLifetime - retirement        = 100 - 30   = 70d
    //   * a fresh CA is created once the newest is within
    //     active / rotation_fraction = 70 / 2 = 35d of expiry, so CAs are born 100 - 35 = 65d apart
    //   * longest leaf handed out = active / rotation_fraction / 2 = 70 / 2 / 2 = 17.5d
    //   * a CA can sign, and be a trust anchor, only until  expiry - retirement
    //
    // The two CAs around one rotation (clock set to the moment the new CA is created):
    //   CA0 (old): created day -65, expires day 35,  usable until day 5   (35 - 30)
    //   CA1 (new): created day 0,   expires day 100, usable until day 70  (100 - 30)
    //
    // Two pods that overlap:
    //   Pod A mounts day -12.5, the latest that still fits under CA0 (a 17.5d leaf ends at day 5).
    //         Signed by CA0, trusts {CA0} (CA1 does not exist yet), alive until day 5.
    //   Pod B mounts day 0. CA0 cannot sign it (a 17.5d leaf runs to day 17.5, past CA0's day 5),
    //         so it is signed by CA1, trusts {CA0, CA1}, alive until day 17.5.
    //
    // On days 0..5 both are alive, but Pod A never learned about CA1, so it cannot verify Pod B's
    // certificate and mTLS between them silently fails. proptest shrinks to an equivalent minimal
    // case such as `ca_lifetime=3600, retirement=115, max_leaf_lifetime=865`.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]
        #[test]
        fn overlapping_pods_mutually_trust(
            // Same generators as `signing_ca_always_available`; see there for the full rationale.
            // caCertificateLifetime: 1 hour up to 400 days, in whole seconds.
            ca_lifetime in 3600i64..=400 * 86400,
            // caCertificateRetirementDuration as a per-mille fraction of the lifetime, covering the
            // whole accepted domain (`retirement < caLifetime`) regardless of the lifetime chosen.
            retirement_permille in 1i64..=999,
            // maxCertificateLifetime requested by the SecretClass, up to 3x the CA lifetime so the
            // clamp both binds and does not.
            requested_max_lifetime in 1i64..=3 * 400 * 86400,
        ) {
            let retirement = (ca_lifetime * retirement_permille / 1000).max(1);
            prop_assume!(retirement < ca_lifetime);

            let max_leaf_lifetime = requested_max_lifetime
                .min(secs(safe_max_cert_lifetime(dur(ca_lifetime), dur(retirement))));
            prop_assume!(max_leaf_lifetime > 0);

            // Every pod mounted over three CA-lifetimes, each carrying its frozen signer and trust
            // set. Check every pair whose validity windows overlap in time: both must trust each
            // other's signer.
            let pods = simulate_pods(ca_lifetime, retirement, max_leaf_lifetime);
            for earlier in 0..pods.len() {
                for later in (earlier + 1)..pods.len() {
                    let (pod_a, pod_b) = (&pods[earlier], &pods[later]);
                    let windows_overlap = pod_a.start < pod_b.end && pod_b.start < pod_a.end;
                    if windows_overlap {
                        prop_assert!(
                            pod_a.trust.contains(&pod_b.signer)
                                && pod_b.trust.contains(&pod_a.signer),
                            "overlap trust gap: A[{},{}] signer={} trust={:?} | B[{},{}] signer={} trust={:?} \
                             (ca_lifetime={ca_lifetime}, retirement={retirement}, max_leaf_lifetime={max_leaf_lifetime})",
                            pod_a.start, pod_a.end, pod_a.signer, pod_a.trust,
                            pod_b.start, pod_b.end, pod_b.signer, pod_b.trust,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn datetime_conversion() {
        // Conversion should preserve timezone and fractional seconds
        assert_eq!(
            time_datetime_to_chrono(
                time::OffsetDateTime::parse("2021-02-04T05:23:00.123+01:00", &Rfc3339).unwrap()
            )
            .unwrap(),
            chrono::DateTime::parse_from_rfc3339("2021-02-04T06:23:00.123+02:00").unwrap()
        );
    }
}
