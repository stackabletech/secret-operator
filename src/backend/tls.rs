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
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::ObjectMetaBuilder,
    k8s_openapi::{api::core::v1::Secret, ByteString},
};
use time::{Duration, OffsetDateTime};

use super::{pod_info::Address, pod_info::PodInfo, SecretBackend, SecretBackendError, SecretFiles};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to build certificate"))]
    BuildCertificate { source: openssl::error::ErrorStack },
    #[snafu(display("failed to generate certificate key"))]
    GenerateKey { source: openssl::error::ErrorStack },
    #[snafu(display("failed to serialize certificate"))]
    SerializeCertificate { source: openssl::error::ErrorStack },
}

impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::BuildCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::GenerateKey { .. } => tonic::Code::Unavailable,
            Error::SerializeCertificate { .. } => tonic::Code::Unavailable,
        }
    }
}

pub struct TlsGenerate {
    ca_cert: X509,
    ca_key: PKey<Private>,
}

impl TlsGenerate {
    pub fn new_self_signed() -> Self {
        let subject_name = X509NameBuilder::new()
            .and_then(|mut name| {
                name.append_entry_by_nid(Nid::COMMONNAME, "secret-operator self-signed")?;
                Ok(name)
            })
            .unwrap()
            .build();
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::minutes(5);
        let not_after = now + Duration::days(2 * 365);
        let conf = Conf::new(ConfMethod::default()).unwrap();
        let ca_key = PKey::try_from(Rsa::generate(2048).unwrap()).unwrap();
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
            .unwrap()
            .build();
        Self { ca_key, ca_cert }
    }

    pub async fn get_or_create_k8s_certificate(
        client: &stackable_operator::client::Client,
    ) -> Self {
        let k8s_secret_name = "secret-provisioner-ca";
        let k8s_ns = "default";
        let existing_secret = client.get::<Secret>(k8s_secret_name, Some(k8s_ns)).await;
        match existing_secret {
            Ok(ca_secret) => {
                let ca_data = ca_secret.data.unwrap_or_default();
                Self {
                    ca_key: PKey::private_key_from_pem(&ca_data.get("ca.key").unwrap().0).unwrap(),
                    ca_cert: X509::from_pem(&ca_data.get("ca.crt").unwrap().0).unwrap(),
                }
            }
            Err(_) => {
                // Failed to get existing cert, try to create a new self-signed one
                let ca = Self::new_self_signed();
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
                                    ByteString(ca.ca_key.private_key_to_pem_pkcs8().unwrap()),
                                ),
                                (
                                    "ca.crt".to_string(),
                                    ByteString(ca.ca_cert.to_pem().unwrap()),
                                ),
                            ]
                            .into(),
                        ),
                        ..Secret::default()
                    })
                    .await
                    .unwrap();
                ca
            }
        }
    }
}

#[async_trait]
impl SecretBackend for TlsGenerate {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: super::SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<SecretFiles, Self::Error> {
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::minutes(5);
        let not_after = now + Duration::days(1);
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
                    for addr in selector.scope_addresses(&pod_info, *scope) {
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
            .context(BuildCertificateSnafu)?
            .build();
        Ok([
            (
                "ca.crt".into(),
                self.ca_cert.to_pem().context(SerializeCertificateSnafu)?,
            ),
            (
                "tls.crt".into(),
                pod_cert.to_pem().context(SerializeCertificateSnafu)?,
            ),
            (
                "tls.key".into(),
                pod_key
                    .private_key_to_pem_pkcs8()
                    .context(SerializeCertificateSnafu)?,
            ),
        ]
        .into())
    }
}
