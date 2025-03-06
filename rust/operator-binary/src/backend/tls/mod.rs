//! Dynamically provisions TLS certificates

use std::ops::Range;

use async_trait::async_trait;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    conf::{Conf, ConfMethod},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
        X509Builder, X509NameBuilder,
    },
};
use rand::Rng;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::chrono::{self, FixedOffset, TimeZone},
    time::Duration,
};
use time::OffsetDateTime;

use super::{
    pod_info::{Address, PodInfo},
    scope::SecretScope,
    ScopeAddressesError, SecretBackend, SecretBackendError, SecretContents,
};
use crate::{
    crd::{self, CertificateKeyGeneration},
    format::{well_known, SecretData, WellKnownSecretData},
    utils::iterator_try_concat_bytes,
};

mod ca;

/// How long CA certificates should last for. Also used for calculating when they should be rotated.
/// [`DEFAULT_MAX_CERT_LIFETIME`] must be less than half of [`DEFAULT_CA_CERT_LIFETIME`].
pub const DEFAULT_CA_CERT_LIFETIME: Duration = Duration::from_days_unchecked(365);

/// As the Pods will be evicted [`DEFAULT_CERT_RESTART_BUFFER`] before
/// the cert actually expires, this results in a restart in approx every 2 weeks,
/// which matches the rolling re-deploy of k8s nodes of e.g.:
/// * 1 week for IONOS
/// * 2 weeks for some on-prem k8s clusters
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

    #[snafu(display("certificate expiring at {expires_at} would schedule the pod to be restarted at {restart_at}, which is in the past (and we don't have a time machine (yet))"))]
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
            Error::TooShortCertLifetimeRequiresTimeTravel { .. } => tonic::Code::InvalidArgument,
            Error::JitterOutOfRange { .. } => tonic::Code::InvalidArgument,
        }
    }
}

#[derive(Debug)]
pub struct TlsGenerate {
    ca_manager: ca::Manager,
    max_cert_lifetime: Duration,
    key_generation: CertificateKeyGeneration,
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
        crd::AutoTlsCa {
            secret: ca_secret,
            auto_generate: auto_generate_ca,
            ca_certificate_lifetime,
            key_generation,
        }: &crd::AutoTlsCa,
        max_cert_lifetime: Duration,
    ) -> Result<Self> {
        Ok(Self {
            ca_manager: ca::Manager::load_or_create(
                client,
                ca_secret,
                &ca::Config {
                    manage_ca: *auto_generate_ca,
                    ca_certificate_lifetime: *ca_certificate_lifetime,
                    rotate_if_ca_expires_before: Some(*ca_certificate_lifetime / 2),
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
        selector: &super::SecretVolumeSelector,
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

        let conf = Conf::new(ConfMethod::default()).unwrap();

        let pod_key_length = match self.key_generation {
            CertificateKeyGeneration::Rsa { length } => length,
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
        let ca = self
            .ca_manager
            .find_certificate_authority_for_signing(not_after)
            .context(PickCaSnafu)?;
        let pod_cert = X509Builder::new()
            .and_then(|mut x509| {
                let subject_name = X509NameBuilder::new()
                    .and_then(|mut name| {
                        name.append_entry_by_nid(Nid::COMMONNAME, "generated certificate for pod")?;
                        Ok(name)
                    })?
                    .build();
                x509.set_subject_name(&subject_name)?;
                x509.set_issuer_name(ca.certificate.subject_name())?;
                x509.set_not_before(Asn1Time::from_unix(not_before.unix_timestamp())?.as_ref())?;
                x509.set_not_after(Asn1Time::from_unix(not_after.unix_timestamp())?.as_ref())?;
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
        Ok(
            SecretContents::new(SecretData::WellKnown(WellKnownSecretData::TlsPem(
                well_known::TlsPem {
                    ca_pem: iterator_try_concat_bytes(
                        self.ca_manager.trust_roots().into_iter().map(|ca| {
                            ca.to_pem()
                                .context(SerializeCertificateSnafu { tpe: CertType::Ca })
                        }),
                    )?,
                    certificate_pem: pod_cert
                        .to_pem()
                        .context(SerializeCertificateSnafu { tpe: CertType::Pod })?,
                    key_pem: pod_key
                        .private_key_to_pem_pkcs8()
                        .context(SerializeCertificateSnafu { tpe: CertType::Pod })?,
                },
            )))
            .expires_after(
                time_datetime_to_chrono(expire_pod_after).context(InvalidCertLifetimeSnafu)?,
            ),
        )
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
    use time::format_description::well_known::Rfc3339;

    use super::{chrono, time_datetime_to_chrono};

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
