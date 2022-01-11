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
use time::{Duration, OffsetDateTime};

use super::{NodeInfo, SecretBackend, SecretBackendError, SecretFiles};

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
    node_info: NodeInfo,
    ca_cert: X509,
    ca_key: PKey<Private>,
}

impl TlsGenerate {
    pub fn new_self_signed(node_info: NodeInfo) -> Self {
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
        Self {
            node_info,
            ca_key,
            ca_cert,
        }
    }
}

#[async_trait]
impl SecretBackend for TlsGenerate {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: super::SecretVolumeSelector,
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
                for scope in &selector.scope {
                    san_ext.dns(&selector.scope_value(&self.node_info, *scope));
                }
                exts.push(san_ext.build(&ctx)?);
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
