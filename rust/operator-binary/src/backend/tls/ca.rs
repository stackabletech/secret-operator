use std::collections::BTreeMap;

use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    conf::{Conf, ConfMethod},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
        X509Builder, X509NameBuilder, X509,
    },
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::{Secret, SecretReference},
        ByteString,
    },
    kube::{
        self,
        api::{
            entry::{self, Entry},
            PostParams,
        },
        runtime::reflector::ObjectRef,
    },
    time::Duration,
};
use time::OffsetDateTime;

use crate::backend::SecretBackendError;

const SECRET_KEY_CERT: &str = "ca.crt";
const SECRET_KEY_KEY: &str = "ca.key";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to generate certificate key"))]
    GenerateKey { source: openssl::error::ErrorStack },

    #[snafu(display("failed to load CA {secret}"))]
    FindCa {
        source: kube::Error,
        secret: ObjectRef<Secret>,
    },

    #[snafu(display("CA {secret} does not exist, and autoGenerate is false"))]
    CaNotFoundAndGenDisabled { secret: ObjectRef<Secret> },

    #[snafu(display("CA secret is missing required certificate file"))]
    MissingCaCertificate,

    #[snafu(display("failed to load certificate from key {key:?} of {secret}"))]
    LoadCertificate {
        source: openssl::error::ErrorStack,
        key: String,
        secret: ObjectRef<Secret>,
    },

    #[snafu(display("invalid secret reference: {secret:?}"))]
    InvalidSecretRef { secret: SecretReference },

    #[snafu(display("failed to build certificate"))]
    BuildCertificate { source: openssl::error::ErrorStack },

    #[snafu(display("failed to serialize certificate"))]
    SerializeCertificate { source: openssl::error::ErrorStack },

    #[snafu(display("failed to save CA certificate to {secret}"))]
    SaveCaCertificate {
        source: entry::CommitError,
        secret: ObjectRef<Secret>,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;

impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::GenerateKey { .. } => tonic::Code::Internal,
            Error::MissingCaCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::FindCa { .. } => tonic::Code::Unavailable,
            Error::CaNotFoundAndGenDisabled { .. } => tonic::Code::FailedPrecondition,
            Error::LoadCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::InvalidSecretRef { .. } => tonic::Code::FailedPrecondition,
            Error::BuildCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SerializeCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SaveCaCertificate { .. } => tonic::Code::Unavailable,
        }
    }
}

pub struct CertificateAuthority {
    pub ca_cert: X509,
    pub ca_key: PKey<Private>,
}

impl CertificateAuthority {
    fn new_self_signed() -> Result<Self> {
        let subject_name = X509NameBuilder::new()
            .and_then(|mut name| {
                name.append_entry_by_nid(Nid::COMMONNAME, "secret-operator self-signed")?;
                Ok(name)
            })
            .context(BuildCertificateSnafu)?
            .build();
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::from_minutes_unchecked(5);
        let not_after = now + Duration::from_days_unchecked(2 * 365);
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
            .context(BuildCertificateSnafu)?
            .build();
        Ok(Self { ca_key, ca_cert })
    }

    fn from_secret(
        secret_data: &BTreeMap<String, ByteString>,
        secret_ref: impl Fn() -> ObjectRef<Secret>,
        key_key: &str,
        cert_key: &str,
    ) -> Result<Self> {
        Ok(CertificateAuthority {
            ca_key: PKey::private_key_from_pem(
                &secret_data
                    .get(key_key)
                    .context(MissingCaCertificateSnafu)?
                    .0,
            )
            .with_context(|_| LoadCertificateSnafu {
                key: key_key,
                secret: secret_ref(),
            })?,
            ca_cert: X509::from_pem(
                &secret_data
                    .get(cert_key)
                    .context(MissingCaCertificateSnafu)?
                    .0,
            )
            .with_context(|_| LoadCertificateSnafu {
                key: cert_key,
                secret: secret_ref(),
            })?,
        })
    }
}

pub struct Manager {
    ca: CertificateAuthority,
}

impl Manager {
    pub async fn load_or_create(
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
        let secret_ref = || ObjectRef::<Secret>::new(k8s_secret_name).within(k8s_ns);
        // Use entry API rather than apply so that we crash and retry on conflicts (to avoid creating spurious certs that we throw away immediately)
        let secrets_api = &client.get_api::<Secret>(k8s_ns);
        let existing_secret =
            secrets_api
                .entry(k8s_secret_name)
                .await
                .with_context(|_| FindCaSnafu {
                    secret: secret_ref(),
                })?;
        let ca;
        let mut ca_secret = match existing_secret {
            Entry::Occupied(ca_secret) => {
                // Existing CA has been found, load and use this
                let empty = BTreeMap::new();
                let ca_data = ca_secret.get().data.as_ref().unwrap_or(&empty);
                ca = CertificateAuthority::from_secret(
                    ca_data,
                    secret_ref,
                    SECRET_KEY_KEY,
                    SECRET_KEY_CERT,
                )?;
                ca_secret
            }
            Entry::Vacant(ca_secret) if auto_generate_if_missing => {
                ca = CertificateAuthority::new_self_signed()?;
                ca_secret.insert(Secret {
                    data: Some(
                        [
                            (
                                SECRET_KEY_KEY.to_string(),
                                ByteString(
                                    ca.ca_key
                                        .private_key_to_pem_pkcs8()
                                        .context(SerializeCertificateSnafu)?,
                                ),
                            ),
                            (
                                SECRET_KEY_CERT.to_string(),
                                ByteString(ca.ca_cert.to_pem().context(SerializeCertificateSnafu)?),
                            ),
                        ]
                        .into(),
                    ),
                    ..Secret::default()
                })
            }
            Entry::Vacant(_) => {
                return CaNotFoundAndGenDisabledSnafu {
                    secret: ObjectRef::new(k8s_secret_name).within(k8s_ns),
                }
                .fail();
            }
        };
        ca_secret
            .commit(&PostParams::default())
            .await
            .context(SaveCaCertificateSnafu {
                secret: ObjectRef::new(k8s_secret_name).within(k8s_ns),
            })?;
        Ok(Self { ca })
    }

    pub fn get_ca(&self) -> &CertificateAuthority {
        &self.ca
    }
}
