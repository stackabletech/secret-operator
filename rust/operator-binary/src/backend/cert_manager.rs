//! Uses TLS certificates provisioned by [cert-manager](https://cert-manager.io/)
//!
//! Requires the Kubernetes cluster to already have cert-manager installed and configured.

use std::collections::HashSet;

use async_trait::async_trait;
use chrono::{DateTime, FixedOffset, TimeDelta, Utc};
use openssl::x509::X509;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{ByteString, api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::Time},
    kube::{api::ObjectMeta, runtime::reflector::ObjectRef},
    shared::time::Duration,
};

use super::{
    ScopeAddressesError, SecretBackend, SecretBackendError, SecretContents, SecretVolumeSelector,
    TrustSelector,
    k8s_search::LABEL_SCOPE_NODE,
    pod_info::{Address, PodInfo, SchedulingPodInfo},
    scope::SecretScope,
};
use crate::{
    crd::v1alpha2,
    external_crd::{self, cert_manager::CertificatePrivateKey},
    format::{SecretData, SecretFiles, well_known::FILE_PEM_CERT_CERT},
    utils::{
        Asn1TimeParseError, DateTimeOutOfBoundsError, Unloggable, asn1time_to_offsetdatetime,
        time_datetime_to_chrono,
    },
};

/// Default lifetime of certs when no annotations are set on the Volume.
pub const DEFAULT_CERT_LIFETIME: Duration = Duration::from_hours_unchecked(24);

const FIELD_MANAGER_SCOPE: &str = "backend.cert-manager";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display(
        "unable to find PersistentVolumeClaim for volume (try deleting and recreating the Pod, ensure you are using the `ephemeral:` volume type, rather than `csi:`)"
    ))]
    NoPvcName,

    #[snafu(display("failed to get addresses for scope {:?}", format!("{scope}")))]
    ScopeAddresses {
        source: ScopeAddressesError,
        scope: SecretScope,
    },

    #[snafu(display("failed to get {secret} (for {certificate})"))]
    GetSecret {
        source: stackable_operator::client::Error,
        secret: ObjectRef<Secret>,
        certificate: ObjectRef<external_crd::cert_manager::Certificate>,
    },

    #[snafu(display("failed to apply {certificate}"))]
    ApplyCertManagerCertificate {
        source: stackable_operator::client::Error,
        certificate: ObjectRef<external_crd::cert_manager::Certificate>,
    },

    #[snafu(display("failed to get {certificate}"))]
    GetCertManagerCertificate {
        source: stackable_operator::client::Error,
        certificate: ObjectRef<external_crd::cert_manager::Certificate>,
    },

    #[snafu(display("failed to read the expiry of {secret} (provisioned by {certificate})"))]
    InvalidProvisionedCertificate {
        source: CertificateExpiryError,
        secret: ObjectRef<Secret>,
        certificate: ObjectRef<external_crd::cert_manager::Certificate>,
    },

    #[snafu(display("the certManager backend does not currently support TrustStore exports"))]
    TrustExportUnsupported,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum CertificateExpiryError {
    #[snafu(display("Secret has no {FILE_PEM_CERT_CERT:?} entry"))]
    NoCertificate,

    #[snafu(display("failed to parse {FILE_PEM_CERT_CERT:?} as a PEM certificate"))]
    ParseCertificate { source: openssl::error::ErrorStack },

    #[snafu(display("failed to read the certificate's validity period"))]
    ReadValidity { source: Asn1TimeParseError },

    #[snafu(display("the certificate's validity period is out of range"))]
    ValidityOutOfBounds { source: DateTimeOutOfBoundsError },

    #[snafu(display("cert-manager reported a renewal time that is out of range: {seconds}s"))]
    RenewalTimeOutOfRange { seconds: i64 },

    #[snafu(display(
        "the provisioned certificate expired at {not_after} and cert-manager has not replaced it (renewal was due at {renewal})"
    ))]
    CertificateAlreadyExpired {
        not_after: DateTime<FixedOffset>,
        renewal: DateTime<FixedOffset>,
    },
}

/// Returns when the Pod holding the certificate provisioned into `secret_data` should be restarted.
///
/// Restarting *at* the certificate's expiry is too late: eviction respects
/// `terminationGracePeriodSeconds` and is serialised by any PodDisruptionBudget, so every replica
/// after the first would keep serving an expired certificate for as long as the rollout takes.
/// So aim for halfway between cert-manager's renewal and the expiry,
/// which also scales with the certificate's lifetime.
fn expire_pod_after(
    secret_data: &SecretFiles,
    renewal_time: Option<&Time>,
    now: DateTime<FixedOffset>,
) -> Result<DateTime<FixedOffset>, CertificateExpiryError> {
    use certificate_expiry_error::*;

    let cert_pem = secret_data
        .get(FILE_PEM_CERT_CERT)
        .context(NoCertificateSnafu)?;
    // Reads the first certificate in the file, which for cert-manager is the leaf.
    // Any intermediates that follow are ignored.
    let cert = X509::from_pem(cert_pem).context(ParseCertificateSnafu)?;
    let not_before = asn1_time_to_chrono(cert.not_before())?;
    let not_after = asn1_time_to_chrono(cert.not_after())?;

    // Prefer cert-manager's own `status.renewalTime`: it accounts for a `renewBefore` that might
    // differ from our requested duration for all kinds of reasons (config etc.).
    // It is empty between our apply and cert-manager's next reconcile, so fall back to its default
    // of renewing two thirds through the certificate's validity.
    let renewal = match renewal_time {
        Some(renewal_time) => {
            let seconds = renewal_time.0.as_second();
            DateTime::from_timestamp(seconds, 0)
                .context(RenewalTimeOutOfRangeSnafu { seconds })?
                .fixed_offset()
        }
        None => {
            let validity: TimeDelta = not_after - not_before;
            let renewal = not_before + validity * 2 / 3;
            tracing::info!(
                certificate.not_before = %not_before,
                certificate.not_after = %not_after,
                certificate.renewal_time = %renewal,
                "Certificate has no status.renewalTime, assuming cert-manager's default of two thirds through the validity period"
            );
            renewal
        }
    };

    // Halfway from renewal to expiry.
    // With the two-thirds fallback that lands on "not_before + 5/6 * validity".
    let remaining: TimeDelta = not_after - renewal;
    let expire_pod_after = renewal + remaining / 2;

    // Reporting an expiry that has already passed would have the restarter evict the Pod at once,
    // and the replacement would be handed this same certificate and evicted again. There is nothing
    // useful to hand out, so fail and let the kubelet retry until cert-manager catches up.
    if not_after <= now {
        return CertificateAlreadyExpiredSnafu { not_after, renewal }.fail();
    }

    if expire_pod_after <= now {
        // cert-manager has not renewed even though it said it would by now, so a restart would hand
        // the Pod back the same certificate and evict it again. Wait for the expiry instead, which
        // the check above guarantees is still in the future.
        tracing::warn!(
            certificate.not_after = %not_after,
            certificate.renewal_time = %renewal,
            "cert-manager has not renewed this certificate yet, falling back to restarting the Pod at its expiry"
        );
        return Ok(not_after);
    }

    Ok(expire_pod_after)
}

fn asn1_time_to_chrono(
    time: &openssl::asn1::Asn1TimeRef,
) -> Result<DateTime<FixedOffset>, CertificateExpiryError> {
    use certificate_expiry_error::*;

    let time = asn1time_to_offsetdatetime(time).context(ReadValiditySnafu)?;
    time_datetime_to_chrono(time).context(ValidityOutOfBoundsSnafu)
}

impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::NoPvcName => tonic::Code::FailedPrecondition,
            Error::ScopeAddresses { .. } => tonic::Code::Unavailable,
            Error::GetSecret { .. } => tonic::Code::Unavailable,
            Error::GetCertManagerCertificate { .. } => tonic::Code::Unavailable,
            Error::ApplyCertManagerCertificate { .. } => tonic::Code::Unavailable,
            Error::InvalidProvisionedCertificate { .. } => tonic::Code::Unavailable,
            Error::TrustExportUnsupported => tonic::Code::FailedPrecondition,
        }
    }

    fn secondary_object(&self) -> Option<ObjectRef<stackable_operator::kube::api::DynamicObject>> {
        match self {
            Error::NoPvcName => None,
            Error::ScopeAddresses { source, .. } => source.secondary_object(),
            Error::GetSecret { secret, .. } => Some(secret.clone().erase()),
            Error::ApplyCertManagerCertificate { certificate, .. } => {
                Some(certificate.clone().erase())
            }
            Error::GetCertManagerCertificate { certificate, .. } => {
                Some(certificate.clone().erase())
            }
            Error::InvalidProvisionedCertificate { secret, .. } => Some(secret.clone().erase()),
            Error::TrustExportUnsupported => None,
        }
    }
}

#[derive(Debug)]
pub struct CertManager {
    // Not secret per se, but Client isn't Debug: https://github.com/stackabletech/secret-operator/issues/411
    pub client: Unloggable<stackable_operator::client::Client>,
    pub config: v1alpha2::CertManagerBackend,
}

#[async_trait]
impl SecretBackend for CertManager {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<SecretContents, Self::Error> {
        let cert_name = selector
            .internal
            .pvc_name
            .as_ref()
            .context(NoPvcNameSnafu)?;
        let mut dns_names = Vec::new();
        let mut ip_addresses = Vec::new();
        for scope in &selector.scope {
            for address in selector
                .scope_addresses(&pod_info, scope)
                .context(ScopeAddressesSnafu { scope })?
            {
                match address {
                    Address::Dns(name) => dns_names.push(name),
                    Address::Ip(addr) => ip_addresses.push(addr.to_string()),
                }
            }
        }
        let cert = external_crd::cert_manager::Certificate {
            metadata: ObjectMeta {
                name: Some(cert_name.clone()),
                namespace: Some(selector.namespace.clone()),
                labels: Some(
                    [pod_info
                        .scheduling
                        .has_node_scope
                        .then(|| (LABEL_SCOPE_NODE.to_string(), pod_info.node_name))]
                    .into_iter()
                    .flatten()
                    .collect(),
                ),
                ..Default::default()
            },
            status: None,
            spec: external_crd::cert_manager::CertificateSpec {
                secret_name: cert_name.clone(),
                duration: Some(format!(
                    "{}s",
                    selector
                        .cert_manager_cert_lifetime
                        .unwrap_or(self.config.default_certificate_lifetime)
                        .as_secs()
                )),
                dns_names,
                ip_addresses,
                issuer_ref: external_crd::cert_manager::ObjectReference {
                    name: self.config.issuer.name.clone(),
                    kind: Some(self.config.issuer.kind.to_string()),
                },
                private_key: match self.config.key_generation {
                    v1alpha2::CertificateKeyGeneration::Rsa { length } => CertificatePrivateKey {
                        algorithm: "RSA".to_string(),
                        size: length,
                    },
                },
            },
        };
        let cert = self
            .client
            .apply_patch(FIELD_MANAGER_SCOPE, &cert, &cert)
            .await
            .with_context(|_| ApplyCertManagerCertificateSnafu {
                certificate: ObjectRef::from_obj(&cert),
            })?;

        let secret_ref =
            ObjectRef::<Secret>::new(&cert.spec.secret_name).within(&selector.namespace);
        let secret = self
            .client
            .get::<Secret>(&cert.spec.secret_name, &selector.namespace)
            .await
            .with_context(|_| GetSecretSnafu {
                certificate: ObjectRef::from_obj(&cert),
                secret: secret_ref.clone(),
            })?;
        let secret_data = secret
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|(k, ByteString(v))| (k, v))
            .collect::<SecretFiles>();

        // cert-manager renews the certificate in the Secret on its own schedule.
        // We copy the material into the pod and never touch it again.
        // This reports an expiry so that the Pod gets restarted (and so picks up the renewed
        // certificate) via the commons-operator restarter mechanism.
        let renewal_time = cert
            .status
            .as_ref()
            .and_then(|status| status.renewal_time.as_ref());
        let expires_after = expire_pod_after(&secret_data, renewal_time, Utc::now().fixed_offset())
            .with_context(|_| InvalidProvisionedCertificateSnafu {
                certificate: ObjectRef::from_obj(&cert),
                secret: secret_ref.clone(),
            })?;

        Ok(SecretContents::new(SecretData::Unknown(secret_data)).expires_after(expires_after))
    }

    async fn get_trust_data(
        &self,
        _selector: &TrustSelector,
    ) -> Result<SecretContents, Self::Error> {
        TrustExportUnsupportedSnafu.fail()
    }

    async fn get_qualified_node_names(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: SchedulingPodInfo,
    ) -> Result<Option<HashSet<String>>, Self::Error> {
        if pod_info.has_node_scope {
            let cert_name = selector
                .internal
                .pvc_name
                .as_deref()
                .context(NoPvcNameSnafu)?;
            Ok(self
                .client
                // If certificate does not already exist, allow scheduling to any node
                .get_opt::<external_crd::cert_manager::Certificate>(cert_name, &selector.namespace)
                .await
                .with_context(|_| GetCertManagerCertificateSnafu {
                    certificate: ObjectRef::<external_crd::cert_manager::Certificate>::new(
                        cert_name,
                    )
                    .within(&selector.namespace),
                })?
                .and_then(|cert| cert.metadata.labels?.remove(LABEL_SCOPE_NODE))
                .map(|node| [node].into()))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use openssl::{asn1::Asn1Time, pkey::PKey, rsa::Rsa, x509::X509Builder};

    use super::*;

    /// The certificates below are all one day long, starting at the epoch.
    const HOUR: i64 = 3600;
    const NOT_BEFORE: i64 = 0;
    const NOT_AFTER: i64 = 24 * HOUR;

    fn certificate_valid_between(not_before: i64, not_after: i64) -> Vec<u8> {
        let pkey = PKey::try_from(Rsa::generate(2048).unwrap()).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder
            .set_not_before(Asn1Time::from_unix(not_before).unwrap().as_ref())
            .unwrap();
        builder
            .set_not_after(Asn1Time::from_unix(not_after).unwrap().as_ref())
            .unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .sign(&pkey, openssl::hash::MessageDigest::sha256())
            .unwrap();
        builder.build().to_pem().unwrap()
    }

    fn secret_with(cert_pem: Vec<u8>) -> SecretFiles {
        SecretFiles::from([(FILE_PEM_CERT_CERT.to_owned(), cert_pem)])
    }

    fn at(timestamp: i64) -> DateTime<FixedOffset> {
        DateTime::from_timestamp(timestamp, 0)
            .unwrap()
            .fixed_offset()
    }

    fn time_at(timestamp: i64) -> Time {
        Time(stackable_operator::k8s_openapi::jiff::Timestamp::from_second(timestamp).unwrap())
    }

    #[test]
    fn pod_expires_halfway_between_cert_managers_renewal_and_the_expiry() {
        let secret_data = secret_with(certificate_valid_between(NOT_BEFORE, NOT_AFTER));

        // Renewal at 12h of a 24h certificate, so the Pod should be restarted at 18h.
        assert_eq!(
            expire_pod_after(&secret_data, Some(&time_at(12 * HOUR)), at(HOUR))
                .unwrap()
                .timestamp(),
            18 * HOUR
        );
    }

    #[test]
    fn without_a_renewal_time_the_default_of_two_thirds_is_assumed() {
        let secret_data = secret_with(certificate_valid_between(NOT_BEFORE, NOT_AFTER));

        // cert-manager renews two thirds in (16h), so halfway to the expiry is 5/6 in (20h).
        assert_eq!(
            expire_pod_after(&secret_data, None, at(HOUR))
                .unwrap()
                .timestamp(),
            20 * HOUR
        );
    }

    #[test]
    fn an_overdue_renewal_falls_back_to_the_expiry() {
        let secret_data = secret_with(certificate_valid_between(NOT_BEFORE, NOT_AFTER));

        // cert-manager said it would renew at 12h and has not, so restarting now would hand the Pod
        // the same certificate back.
        assert_eq!(
            expire_pod_after(&secret_data, Some(&time_at(12 * HOUR)), at(23 * HOUR))
                .unwrap()
                .timestamp(),
            NOT_AFTER
        );
    }

    #[test]
    fn only_the_leaf_of_a_certificate_chain_is_read() {
        let mut chain = certificate_valid_between(NOT_BEFORE, NOT_AFTER);
        // An intermediate outliving the leaf, as a real chain would have.
        chain.extend(certificate_valid_between(NOT_BEFORE, 365 * 24 * HOUR));

        assert_eq!(
            expire_pod_after(&secret_with(chain), None, at(HOUR))
                .unwrap()
                .timestamp(),
            20 * HOUR
        );
    }

    #[test]
    fn an_already_expired_certificate_is_an_error() {
        let secret_data = secret_with(certificate_valid_between(NOT_BEFORE, NOT_AFTER));

        // Reporting an expiry in the past would have the restarter evict the Pod immediately, and
        // the replacement would be handed this same certificate.
        assert!(matches!(
            expire_pod_after(&secret_data, Some(&time_at(16 * HOUR)), at(30 * HOUR)),
            Err(CertificateExpiryError::CertificateAlreadyExpired { .. })
        ));
    }

    #[test]
    fn expiry_of_secret_without_certificate_is_an_error() {
        assert!(matches!(
            expire_pod_after(&SecretFiles::new(), None, at(HOUR)),
            Err(CertificateExpiryError::NoCertificate)
        ));
    }

    #[test]
    fn expiry_of_unparseable_certificate_is_an_error() {
        let secret_data = secret_with(b"not a certificate".to_vec());

        assert!(matches!(
            expire_pod_after(&secret_data, None, at(HOUR)),
            Err(CertificateExpiryError::ParseCertificate { .. })
        ));
    }
}
