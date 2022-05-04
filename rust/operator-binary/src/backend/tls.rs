//! Dynamically provisions TLS certificates

use async_trait::async_trait;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    conf::{Conf, ConfMethod},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{
            AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage,
            SubjectAlternativeName, SubjectKeyIdentifier,
        },
        X509Builder, X509NameBuilder, X509,
    },
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    builder::ObjectMetaBuilder,
    k8s_openapi::{
        api::core::v1::{Secret, SecretReference},
        chrono::{self, FixedOffset, TimeZone},
        ByteString,
    },
    kube::runtime::reflector::ObjectRef,
};
use time::{Duration, OffsetDateTime};

use super::{
    pod_info::Address, pod_info::PodInfo, SecretBackend, SecretBackendError, SecretContents,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to generate certificate key"))]
    GenerateKey { source: openssl::error::ErrorStack },
    #[snafu(display("could not find CA {secret}, and autoGenerate is false"))]
    FindCaAndGenDisabled {
        source: stackable_operator::error::Error,
        secret: ObjectRef<Secret>,
    },
    #[snafu(display("CA secret is missing required certificate file"))]
    MissingCaCertificate,
    #[snafu(display("failed to load {tpe:?} certificate"))]
    LoadCertificate {
        source: openssl::error::ErrorStack,
        tpe: CertType,
    },
    #[snafu(display("invalid secret reference: {secret:?}"))]
    InvalidSecretRef { secret: SecretReference },
    #[snafu(display("failed to build {tpe:?} certificate"))]
    BuildCertificate {
        source: openssl::error::ErrorStack,
        tpe: CertType,
    },
    #[snafu(display("failed to serialize {tpe:?} certificate"))]
    SerializeCertificate {
        source: openssl::error::ErrorStack,
        tpe: CertType,
    },
    #[snafu(display("failed to save CA certificate to {secret}"))]
    SaveCaCertificate {
        source: stackable_operator::error::Error,
        secret: ObjectRef<Secret>,
    },
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
            Error::GenerateKey { .. } => tonic::Code::Internal,
            Error::FindCaAndGenDisabled { .. } => tonic::Code::FailedPrecondition,
            Error::MissingCaCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::LoadCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::InvalidSecretRef { .. } => tonic::Code::FailedPrecondition,
            Error::BuildCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SerializeCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SaveCaCertificate { .. } => tonic::Code::Unavailable,
        }
    }
}

pub struct TlsGenerate {
    ca_cert: X509,
    ca_key: PKey<Private>,
}

impl TlsGenerate {
    pub fn new_self_signed() -> Result<Self> {
        let subject_name = X509NameBuilder::new()
            .and_then(|mut name| {
                name.append_entry_by_nid(Nid::COMMONNAME, "secret-operator self-signed")?;
                Ok(name)
            })
            .context(BuildCertificateSnafu { tpe: CertType::Ca })?
            .build();
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::minutes(5);
        let not_after = now + Duration::days(2 * 365);
        let conf = Conf::new(ConfMethod::default()).unwrap();
        let ca_key = Rsa::generate(2048)
            .and_then(PKey::try_from)
            .context(GenerateKeySnafu)?;
        let ca_cert = X509Builder::new()
            .and_then(|mut x509| {
                x509.set_subject_name(&subject_name)?;
                x509.set_issuer_name(&subject_name)?;
                x509.set_not_before(Asn1Time::from_unix(not_before.unix_timestamp())?.as_ref())?;
                x509.set_not_after(Asn1Time::from_unix(not_after.unix_timestamp())?.as_ref())?;
                x509.set_pubkey(&ca_key)?;
                let mut serial = BigNum::new()?;
                serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
                x509.set_serial_number(Asn1Integer::from_bn(&serial)?.as_ref())?;
                x509.set_version(
                    3 - 1, // zero-indexed
                )?;
                let ctx = x509.x509v3_context(None, Some(&conf));
                let exts = [
                    BasicConstraints::new().critical().ca().build()?,
                    SubjectKeyIdentifier::new().build(&ctx)?,
                    AuthorityKeyIdentifier::new()
                        .issuer(false)
                        .keyid(false)
                        .build(&ctx)?,
                    KeyUsage::new()
                        .critical()
                        .digital_signature()
                        .key_cert_sign()
                        .crl_sign()
                        .build()?,
                ];
                for ext in exts {
                    x509.append_extension(ext)?;
                }
                x509.sign(&ca_key, MessageDigest::sha256())?;
                Ok(x509)
            })
            .context(BuildCertificateSnafu { tpe: CertType::Ca })?
            .build();
        Ok(Self { ca_key, ca_cert })
    }

    /// Check if a signing CA has already been instantiated in a specified Kubernetes secret - if
    /// one is found the key is loaded and used for signing certs.
    /// If no current authority can be found, a new keypair and self signed certificate is created
    /// and stored for future use.
    /// This allows users to provide their own CA files, but also enables using this for dev and test
    /// scenarios where self signed, ephemeral CAs are ok to use.
    pub async fn get_or_create_k8s_certificate(
        client: &stackable_operator::client::Client,
        secret_ref: &SecretReference,
        auto_generate_if_missing: bool,
    ) -> Result<Self> {
        let (k8s_secret_name, k8s_ns) = match secret_ref {
            SecretReference {
                name: Some(name),
                namespace: Some(ns),
            } => (name, ns),
            _ => {
                return InvalidSecretRefSnafu {
                    secret: secret_ref.clone(),
                }
                .fail()
            }
        };
        let existing_secret = client.get::<Secret>(k8s_secret_name, Some(k8s_ns)).await;
        Ok(match existing_secret {
            Ok(ca_secret) => {
                // Existing CA has been found, load and use this
                let ca_data = ca_secret.data.unwrap_or_default();
                Self {
                    ca_key: PKey::private_key_from_pem(
                        &ca_data.get("ca.key").context(MissingCaCertificateSnafu)?.0,
                    )
                    .context(LoadCertificateSnafu { tpe: CertType::Ca })?,
                    ca_cert: X509::from_pem(
                        &ca_data.get("ca.crt").context(MissingCaCertificateSnafu)?.0,
                    )
                    .context(LoadCertificateSnafu { tpe: CertType::Ca })?,
                }
            }
            Err(_) if auto_generate_if_missing => {
                // Failed to get existing cert, try to create a new self-signed one
                let ca = Self::new_self_signed()?;
                // Use create rather than apply so that we crash and retry on conflicts (to avoid creating spurious certs that we throw away immediately)
                client
                    .create(&Secret {
                        metadata: ObjectMetaBuilder::new()
                            .namespace(k8s_ns)
                            .name(k8s_secret_name)
                            .build(),
                        data: Some(
                            [
                                (
                                    "ca.key".to_string(),
                                    ByteString(ca.ca_key.private_key_to_pem_pkcs8().context(
                                        SerializeCertificateSnafu { tpe: CertType::Ca },
                                    )?),
                                ),
                                (
                                    "ca.crt".to_string(),
                                    ByteString(ca.ca_cert.to_pem().context(
                                        SerializeCertificateSnafu { tpe: CertType::Ca },
                                    )?),
                                ),
                            ]
                            .into(),
                        ),
                        ..Secret::default()
                    })
                    .await
                    .context(SaveCaCertificateSnafu {
                        secret: ObjectRef::new(k8s_secret_name).within(k8s_ns),
                    })?;
                ca
            }
            Err(err) => {
                return Err(err).context(FindCaAndGenDisabledSnafu {
                    secret: ObjectRef::new(k8s_secret_name).within(k8s_ns),
                });
            }
        })
    }
}

#[async_trait]
impl SecretBackend for TlsGenerate {
    type Error = Error;

    /// Generate a keypair and sign it with the CA key.
    /// Then add the ca certificate and return these files for provisioning to the volume.
    async fn get_secret_data(
        &self,
        selector: &super::SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<SecretContents, Self::Error> {
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::minutes(5);
        let not_after = now + Duration::days(1);
        let expire_pod_after = not_after - Duration::minutes(30);
        let conf = Conf::new(ConfMethod::default()).unwrap();
        let pod_key = Rsa::generate(2048)
            .and_then(PKey::try_from)
            .context(GenerateKeySnafu)?;
        let pod_cert = X509Builder::new()
            .and_then(|mut x509| {
                let subject_name = X509NameBuilder::new()
                    .and_then(|mut name| {
                        name.append_entry_by_nid(Nid::COMMONNAME, "generated certificate for pod")?;
                        Ok(name)
                    })?
                    .build();
                x509.set_subject_name(&subject_name)?;
                x509.set_issuer_name(self.ca_cert.issuer_name())?;
                x509.set_not_before(Asn1Time::from_unix(not_before.unix_timestamp())?.as_ref())?;
                x509.set_not_after(Asn1Time::from_unix(not_after.unix_timestamp())?.as_ref())?;
                x509.set_pubkey(&pod_key)?;
                x509.set_version(
                    3 - 1, // zero-indexed
                )?;
                let mut serial = BigNum::new()?;
                serial.rand(64, MsbOption::MAYBE_ZERO, false)?;
                x509.set_serial_number(Asn1Integer::from_bn(&serial)?.as_ref())?;
                let ctx = x509.x509v3_context(Some(&self.ca_cert), Some(&conf));
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
                for scope in &selector.scope {
                    for addr in selector.scope_addresses(&pod_info, scope) {
                        has_san = true;
                        match addr {
                            Address::Dns(dns) => san_ext.dns(&dns),
                            Address::Ip(ip) => san_ext.ip(&ip.to_string()),
                        };
                    }
                }
                if has_san {
                    exts.push(san_ext.build(&ctx)?);
                }
                for ext in exts {
                    x509.append_extension(ext)?;
                }
                x509.sign(&self.ca_key, MessageDigest::sha256())?;
                Ok(x509)
            })
            .context(BuildCertificateSnafu { tpe: CertType::Pod })?
            .build();
        Ok(SecretContents::new(
            [
                (
                    "ca.crt".into(),
                    self.ca_cert
                        .to_pem()
                        .context(SerializeCertificateSnafu { tpe: CertType::Pod })?,
                ),
                (
                    "tls.crt".into(),
                    pod_cert
                        .to_pem()
                        .context(SerializeCertificateSnafu { tpe: CertType::Pod })?,
                ),
                (
                    "tls.key".into(),
                    pod_key
                        .private_key_to_pem_pkcs8()
                        .context(SerializeCertificateSnafu { tpe: CertType::Pod })?,
                ),
            ]
            .into(),
        )
        .expires_after(time_datetime_to_chrono(expire_pod_after)))
    }
}

fn time_datetime_to_chrono(dt: time::OffsetDateTime) -> chrono::DateTime<FixedOffset> {
    let tz = chrono::FixedOffset::east(dt.offset().whole_seconds());
    tz.timestamp(dt.unix_timestamp(), dt.nanosecond())
}

#[cfg(test)]
mod tests {
    use time::format_description::well_known::Rfc3339;

    use super::chrono;
    use super::time_datetime_to_chrono;

    #[test]
    fn datetime_conversion() {
        // Conversion should preserve timezone and fractional seconds
        assert_eq!(
            time_datetime_to_chrono(
                time::OffsetDateTime::parse("2021-02-04T05:23:00.123+01:00", &Rfc3339).unwrap()
            ),
            chrono::DateTime::parse_from_rfc3339("2021-02-04T06:23:00.123+02:00").unwrap()
        );
    }
}
