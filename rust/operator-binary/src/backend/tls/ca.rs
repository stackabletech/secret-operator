use std::collections::BTreeMap;

use openssl::{
    asn1::{Asn1Integer, Asn1Time, Asn1TimeRef, TimeDiff},
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
use tracing::{info, warn};

use crate::backend::SecretBackendError;

const SECRET_KEY_LEGACY_CERT: &str = "ca.crt";
const SECRET_KEY_LEGACY_KEY: &str = "ca.key";
const SECRET_KEY_CERT_SUFFIX: &str = ".ca.crt";
const SECRET_KEY_KEY_SUFFIX: &str = ".ca.key";

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

    #[snafu(display("failed to parse CA lifetime from key {key:?} of {secret}"))]
    ParseLifetime {
        source: Asn1TimeParseError,
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

    #[snafu(display("CA save was requested but automatic management is disabled"))]
    SaveRequestedButForbidden,
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
            Error::ParseLifetime { .. } => tonic::Code::FailedPrecondition,
            Error::InvalidSecretRef { .. } => tonic::Code::FailedPrecondition,
            Error::BuildCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SerializeCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SaveCaCertificate { .. } => tonic::Code::Unavailable,
            Error::SaveRequestedButForbidden { .. } => tonic::Code::FailedPrecondition,
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum GetCaError {
    #[snafu(display("No CA will live until at least {cutoff}"))]
    NoCaLivesLongEnough { cutoff: OffsetDateTime },
}

impl SecretBackendError for GetCaError {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            GetCaError::NoCaLivesLongEnough { .. } => tonic::Code::FailedPrecondition,
        }
    }
}

pub struct CertificateAuthority {
    pub ca_cert: X509,
    pub ca_key: PKey<Private>,
    not_after: OffsetDateTime,
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
        Ok(Self {
            ca_key,
            ca_cert,
            not_after,
        })
    }

    fn from_secret(
        secret_data: &BTreeMap<String, ByteString>,
        secret_ref: impl Fn() -> ObjectRef<Secret>,
        key_key: &str,
        cert_key: &str,
    ) -> Result<Self> {
        let ca_cert = X509::from_pem(
            &secret_data
                .get(cert_key)
                .context(MissingCaCertificateSnafu)?
                .0,
        )
        .with_context(|_| LoadCertificateSnafu {
            key: cert_key,
            secret: secret_ref(),
        })?;
        let ca_key = PKey::private_key_from_pem(
            &secret_data
                .get(key_key)
                .context(MissingCaCertificateSnafu)?
                .0,
        )
        .with_context(|_| LoadCertificateSnafu {
            key: key_key,
            secret: secret_ref(),
        })?;
        Ok(CertificateAuthority {
            not_after: asn1time_to_offsetdatetime(ca_cert.not_after()).with_context(|_| {
                ParseLifetimeSnafu {
                    key: cert_key,
                    secret: secret_ref(),
                }
            })?,
            ca_cert,
            ca_key,
        })
    }
}

pub struct Manager {
    cas: Vec<CertificateAuthority>,
}

impl Manager {
    pub async fn load_or_create(
        client: &stackable_operator::client::Client,
        secret_ref: &SecretReference,
        auto_generate_if_missing: bool,
        rotate_ca_if_expiring_before: Option<Duration>,
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
        let ca_secret = secrets_api
            .entry(k8s_secret_name)
            .await
            .with_context(|_| FindCaSnafu {
                secret: secret_ref(),
            })?;
        let mut update_ca_secret = false;
        let mut cas = match &ca_secret {
            Entry::Occupied(ca_secret) => {
                // Existing CA has been found, load and use this
                let empty = BTreeMap::new();
                let ca_data = ca_secret.get().data.as_ref().unwrap_or(&empty);
                if ca_data.contains_key(SECRET_KEY_LEGACY_CERT) {
                    if auto_generate_if_missing {
                        update_ca_secret = true;
                        info!(
                            secret = %secret_ref(),
                            "Migrating CA secret from legacy naming scheme"
                        );
                    } else {
                        warn!(
                            secret = %secret_ref(),
                            "CA secret uses legacy certificate naming ({SECRET_KEY_LEGACY_CERT}), please rename to 0{SECRET_KEY_CERT_SUFFIX}"
                        );
                    }
                    vec![CertificateAuthority::from_secret(
                        ca_data,
                        secret_ref,
                        SECRET_KEY_LEGACY_KEY,
                        SECRET_KEY_LEGACY_CERT,
                    )?]
                } else {
                    ca_data
                        .keys()
                        .filter_map(|cert_key| {
                            Some(CertificateAuthority::from_secret(
                                ca_data,
                                secret_ref,
                                &cert_key.contains(SECRET_KEY_CERT_SUFFIX).then(|| {
                                    cert_key.replace(SECRET_KEY_CERT_SUFFIX, SECRET_KEY_KEY_SUFFIX)
                                })?,
                                cert_key,
                            ))
                        })
                        .collect::<Result<_>>()?
                }
            }
            Entry::Vacant(_) if auto_generate_if_missing => {
                update_ca_secret = true;
                info!(
                    secret = %secret_ref(),
                    "Provisioning a new CA certificate, because it could not be found"
                );
                vec![CertificateAuthority::new_self_signed()?]
            }
            Entry::Vacant(_) => {
                return CaNotFoundAndGenDisabledSnafu {
                    secret: ObjectRef::new(k8s_secret_name).within(k8s_ns),
                }
                .fail();
            }
        };
        let newest_ca = cas.iter().map(|ca| ca.not_after).max();
        if let (Some(cutoff_duration), Some(newest_ca)) = (rotate_ca_if_expiring_before, newest_ca)
        {
            let cutoff = OffsetDateTime::now_utc() + cutoff_duration;
            if newest_ca < cutoff {
                if auto_generate_if_missing {
                    update_ca_secret = true;
                    info!(
                        secret = %secret_ref(),
                        %cutoff,
                        cutoff.duration = %cutoff_duration,
                        ca_expires_at = %newest_ca,
                        "Provisioning a new CA certificate, because the old one will soon expire"
                    );
                    cas.push(CertificateAuthority::new_self_signed()?);
                } else {
                    warn!(
                        secret = %secret_ref(),
                        %cutoff,
                        cutoff.duration = %cutoff_duration,
                        ca_expires_at = %newest_ca,
                        "CA certificate will soon expire, please provision a new one to prepare for rotation"
                    );
                }
            } else {
                info!(
                    secret = %secret_ref(),
                    %cutoff,
                    cutoff.duration = %cutoff_duration,
                    ca_expires_at = %newest_ca,
                    "CA is not close to expiring, will not initiate rotation"
                );
            }
        }
        if update_ca_secret {
            if auto_generate_if_missing {
                info!(secret = %secret_ref(), "CA has been modified, saving");
                let mut ca_secret = ca_secret.or_insert(Secret::default);
                ca_secret.get_mut().data = Some(
                    cas.iter()
                        .enumerate()
                        .flat_map(|(i, ca)| {
                            [
                                ca.ca_key
                                    .private_key_to_pem_pkcs8()
                                    .context(SerializeCertificateSnafu)
                                    .map(|key| {
                                        (format!("{i}{SECRET_KEY_KEY_SUFFIX}"), ByteString(key))
                                    }),
                                ca.ca_cert.to_pem().context(SerializeCertificateSnafu).map(
                                    |cert| {
                                        (format!("{i}{SECRET_KEY_CERT_SUFFIX}"), ByteString(cert))
                                    },
                                ),
                            ]
                        })
                        .collect::<Result<_>>()?,
                );
                ca_secret
                    .commit(&PostParams::default())
                    .await
                    .context(SaveCaCertificateSnafu {
                        secret: ObjectRef::new(k8s_secret_name).within(k8s_ns),
                    })?;
            } else {
                return SaveRequestedButForbiddenSnafu.fail();
            }
        }
        Ok(Self { cas })
    }

    pub fn get_ca(
        &self,
        valid_until_at_least: OffsetDateTime,
    ) -> Result<&CertificateAuthority, GetCaError> {
        use get_ca_error::*;
        self.cas
            .iter()
            .filter(|ca| ca.not_after > valid_until_at_least)
            // pick the oldest valid CA, since it will be trusted by the most peers
            .min_by_key(|ca| ca.not_after)
            .context(NoCaLivesLongEnoughSnafu {
                cutoff: valid_until_at_least,
            })
    }

    pub fn all_cas(&self) -> impl IntoIterator<Item = &CertificateAuthority> + '_ {
        &self.cas
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Asn1TimeParseError {
    #[snafu(display("unix epoch is not a valid Asn1Time"))]
    Epoch { source: openssl::error::ErrorStack },
    #[snafu(display("unable to diff Asn1Time"))]
    Diff { source: openssl::error::ErrorStack },
    #[snafu(display("unable to parse as OffsetDateTime"))]
    Parse { source: time::error::ComponentRange },
}

fn asn1time_to_offsetdatetime(asn: &Asn1TimeRef) -> Result<OffsetDateTime, Asn1TimeParseError> {
    use asn1_time_parse_error::*;
    const SECS_PER_DAY: i64 = 60 * 60 * 24;
    let epoch = Asn1Time::from_unix(0).context(EpochSnafu)?;
    let TimeDiff { days, secs } = epoch.diff(asn).context(DiffSnafu)?;
    OffsetDateTime::from_unix_timestamp(i64::from(days) * SECS_PER_DAY + i64::from(secs))
        .context(ParseSnafu)
}
