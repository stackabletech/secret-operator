//! Dynamically provisions and picks Certificate Authorities.

use std::{collections::BTreeMap, ffi::OsStr, fmt::Display, path::Path};

use kube_runtime::reflector::Lookup;
use openssl::{
    asn1::{Asn1Integer, Asn1Time},
    bn::{BigNum, MsbOption},
    conf::{Conf, ConfMethod},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509, X509Builder, X509NameBuilder,
        extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    },
};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        ByteString,
        api::core::v1::{ConfigMap, Secret},
    },
    kube::{
        self,
        api::{
            DynamicObject, PostParams,
            entry::{self, Entry},
        },
        runtime::reflector::ObjectRef,
    },
    time::Duration,
};
use stackable_secret_operator_crd_utils::{ConfigMapReference, SecretReference};
use time::OffsetDateTime;
use tracing::{info, info_span, warn};

use crate::{
    backend::SecretBackendError,
    crd::{AdditionalTrustRoot, CertificateKeyGeneration},
    utils::{Asn1TimeParseError, Unloggable, asn1time_to_offsetdatetime},
};

/// v1 format: support a single cert/pkey pair
mod secret_v1_keys {
    pub const CERTIFICATE: &str = "ca.crt";
    pub const PRIVATE_KEY: &str = "ca.key";
}

/// v2 format: support multiple cert/pkey pairs, prefixed by `{i}.`
mod secret_v2_key_suffixes {
    pub const CERTIFICATE: &str = ".ca.crt";
    pub const PRIVATE_KEY: &str = ".ca.key";
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to generate certificate key"))]
    GenerateKey { source: openssl::error::ErrorStack },

    #[snafu(display("failed to load CA from {secret}"))]
    FindCertificateAuthority {
        source: kube::Error,
        secret: ObjectRef<Secret>,
    },

    #[snafu(display("failed to load extra trust root from {object}"))]
    FindExtraTrustRoot {
        source: stackable_operator::client::Error,
        object: ObjectRef<DynamicObject>,
    },

    #[snafu(display("CA {secret} does not exist, and autoGenerate is false"))]
    CaNotFoundAndGenDisabled { secret: ObjectRef<Secret> },

    #[snafu(display("CA {secret} is missing required key {key:?}"))]
    MissingCertificate {
        key: String,
        secret: ObjectRef<Secret>,
    },

    #[snafu(display("failed to load certificate from key {key:?} of {object}"))]
    LoadCertificate {
        source: openssl::error::ErrorStack,
        key: String,
        object: ObjectRef<DynamicObject>,
    },

    #[snafu(display(
        "unsupported certificate format in key {key:?} of {object}; supported extensions: .crt, .der"
    ))]
    UnsupportedCertificateFormat {
        key: String,
        object: ObjectRef<DynamicObject>,
    },

    #[snafu(display("failed to parse CA lifetime from key {key:?} of {secret}"))]
    ParseLifetime {
        source: Asn1TimeParseError,
        key: String,
        secret: ObjectRef<Secret>,
    },

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
            Error::MissingCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::FindCertificateAuthority { .. } => tonic::Code::Unavailable,
            Error::FindExtraTrustRoot { .. } => tonic::Code::Unavailable,
            Error::CaNotFoundAndGenDisabled { .. } => tonic::Code::FailedPrecondition,
            Error::LoadCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::UnsupportedCertificateFormat { .. } => tonic::Code::InvalidArgument,
            Error::ParseLifetime { .. } => tonic::Code::FailedPrecondition,
            Error::BuildCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SerializeCertificate { .. } => tonic::Code::FailedPrecondition,
            Error::SaveCaCertificate { .. } => tonic::Code::Unavailable,
            Error::SaveRequestedButForbidden { .. } => tonic::Code::FailedPrecondition,
        }
    }

    fn secondary_object(&self) -> Option<ObjectRef<kube::api::DynamicObject>> {
        match self {
            Error::GenerateKey { .. } => None,
            Error::FindCertificateAuthority { secret, .. } => Some(secret.clone().erase()),
            Error::FindExtraTrustRoot { object, .. } => Some(object.clone()),
            Error::CaNotFoundAndGenDisabled { secret } => Some(secret.clone().erase()),
            Error::MissingCertificate { secret, .. } => Some(secret.clone().erase()),
            Error::LoadCertificate { object, .. } => Some(object.clone()),
            Error::UnsupportedCertificateFormat { object, .. } => Some(object.clone()),
            Error::ParseLifetime { secret, .. } => Some(secret.clone().erase()),
            Error::BuildCertificate { .. } => None,
            Error::SerializeCertificate { .. } => None,
            Error::SaveCaCertificate { secret, .. } => Some(secret.clone().erase()),
            Error::SaveRequestedButForbidden => None,
        }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum GetCaError {
    #[snafu(display("no CA in {secret} will live until at least {cutoff}"))]
    NoCaLivesLongEnough {
        cutoff: OffsetDateTime,
        secret: ObjectRef<Secret>,
    },
}

impl SecretBackendError for GetCaError {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            GetCaError::NoCaLivesLongEnough { .. } => tonic::Code::FailedPrecondition,
        }
    }

    fn secondary_object(&self) -> Option<ObjectRef<kube::api::DynamicObject>> {
        match self {
            GetCaError::NoCaLivesLongEnough { secret, .. } => Some(secret.clone().erase()),
        }
    }
}

#[derive(Debug)]
pub struct Config {
    /// Whether [`Manager`] is allowed to automatically provision and manage this CA.
    ///
    /// If `false`, logs will be emitted where Secret Operator would have taken action.
    pub manage_ca: bool,

    /// The duration of any new CA certificates provisioned.
    pub ca_certificate_lifetime: Duration,

    /// If no existing CA certificate outlives `rotate_if_ca_expires_before`, a new
    /// certificate will be generated.
    ///
    /// To ensure compatibility with pods that have already been started, the old CA
    /// will still be used as long as the provisioned certificate's lifetime fits
    /// inside the old CA's. This allows the new CA to be gradually introduced to all
    /// pods' truststores.
    ///
    /// Hence, this value _should_ be larger than the PKI's maximum certificate lifetime,
    /// and smaller than [`Self::ca_certificate_lifetime`].
    pub rotate_if_ca_expires_before: Option<Duration>,

    /// Configuration how TLS private keys should be created.
    pub key_generation: CertificateKeyGeneration,
}

/// A single certificate authority certificate.
#[derive(Debug)]
pub struct CertificateAuthority {
    pub certificate: X509,
    pub private_key: Unloggable<PKey<Private>>,
    not_after: OffsetDateTime,
}

impl Display for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertificateAuthority(serial=")?;
        match self.certificate.serial_number().to_bn() {
            Ok(sn) => write!(f, "{}", sn)?,
            Err(_) => f.write_str("<invalid>")?,
        }
        f.write_str(")")
    }
}

impl CertificateAuthority {
    /// Generate a new self-signed CA with a random key.
    fn new_self_signed(config: &Config) -> Result<Self> {
        let subject_name = X509NameBuilder::new()
            .and_then(|mut name| {
                name.append_entry_by_nid(Nid::COMMONNAME, "secret-operator self-signed")?;
                Ok(name)
            })
            .context(BuildCertificateSnafu)?
            .build();
        let now = OffsetDateTime::now_utc();
        let not_before = now - Duration::from_minutes_unchecked(5);
        let not_after = now + config.ca_certificate_lifetime;
        let conf =
            Conf::new(ConfMethod::default()).expect("failed to initialize OpenSSL configuration");

        let private_key_length = match config.key_generation {
            CertificateKeyGeneration::Rsa { length } => length,
        };

        let private_key = Rsa::generate(private_key_length)
            .and_then(PKey::try_from)
            .context(GenerateKeySnafu)?;
        let certificate = X509Builder::new()
            .and_then(|mut x509| {
                x509.set_subject_name(&subject_name)?;
                x509.set_issuer_name(&subject_name)?;
                x509.set_not_before(Asn1Time::from_unix(not_before.unix_timestamp())?.as_ref())?;
                x509.set_not_after(Asn1Time::from_unix(not_after.unix_timestamp())?.as_ref())?;
                x509.set_pubkey(&private_key)?;
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
                x509.sign(&private_key, MessageDigest::sha256())?;
                Ok(x509)
            })
            .context(BuildCertificateSnafu)?
            .build();
        Ok(Self {
            private_key: Unloggable(private_key),
            certificate,
            not_after,
        })
    }

    /// Loads an existing CA from the data of a [`Secret`].
    fn from_secret_data(
        secret_data: &BTreeMap<String, ByteString>,
        secret_ref: &SecretReference,
        key_certificate: &str,
        key_private_key: &str,
    ) -> Result<Self> {
        let certificate = X509::from_pem(
            &secret_data
                .get(key_certificate)
                .context(MissingCertificateSnafu {
                    key: key_certificate,
                    secret: secret_ref,
                })?
                .0,
        )
        .with_context(|_| LoadCertificateSnafu {
            key: key_certificate,
            object: secret_ref,
        })?;
        let private_key = PKey::private_key_from_pem(
            &secret_data
                .get(key_private_key)
                .context(MissingCertificateSnafu {
                    key: key_private_key,
                    secret: secret_ref,
                })?
                .0,
        )
        .with_context(|_| LoadCertificateSnafu {
            key: key_private_key,
            object: secret_ref,
        })?;
        Ok(CertificateAuthority {
            not_after: asn1time_to_offsetdatetime(certificate.not_after()).with_context(|_| {
                ParseLifetimeSnafu {
                    key: key_certificate,
                    secret: secret_ref,
                }
            })?,
            certificate,
            private_key: Unloggable(private_key),
        })
    }
}

/// Manages multiple [`CertificateAuthorities`](`CertificateAuthority`), rotating them as needed.
#[derive(Debug)]
pub struct Manager {
    source_secret: ObjectRef<Secret>,
    certificate_authorities: Vec<CertificateAuthority>,
    additional_trusted_certificates: Vec<X509>,
}

impl Manager {
    pub async fn load_or_create(
        client: &stackable_operator::client::Client,
        secret_ref: &SecretReference,
        additional_trust_roots: &[AdditionalTrustRoot],
        config: &Config,
    ) -> Result<Self> {
        // Use entry API rather than apply so that we crash and retry on conflicts (to avoid creating spurious certs that we throw away immediately)
        let secrets_api = &client.get_api::<Secret>(&secret_ref.namespace);
        let mut ca_secret = secrets_api
            .entry(&secret_ref.name)
            .await
            .with_context(|_| FindCertificateAuthoritySnafu { secret: secret_ref })?;
        let mut update_ca_secret = false;
        let mut certificate_authorities = match &ca_secret {
            Entry::Occupied(ca_secret) => {
                // Existing CA has been found, load and use this
                let empty = BTreeMap::new();
                let ca_data = ca_secret.get().data.as_ref().unwrap_or(&empty);
                if ca_data.contains_key(secret_v1_keys::CERTIFICATE) {
                    if config.manage_ca {
                        update_ca_secret = true;
                        info!(
                            secret = %secret_ref,
                            "Migrating CA secret from legacy naming scheme"
                        );
                    } else {
                        warn!(
                            secret = %secret_ref,
                            "CA secret uses legacy certificate naming ({v1}), please rename to 0{v2}",
                            v1 = secret_v1_keys::CERTIFICATE,
                            v2 = secret_v2_key_suffixes::CERTIFICATE,
                        );
                    }
                    vec![CertificateAuthority::from_secret_data(
                        ca_data,
                        secret_ref,
                        secret_v1_keys::CERTIFICATE,
                        secret_v1_keys::PRIVATE_KEY,
                    )?]
                } else {
                    ca_data
                        .keys()
                        .filter_map(|cert_key| {
                            Some(CertificateAuthority::from_secret_data(
                                ca_data,
                                secret_ref,
                                cert_key,
                                &cert_key
                                    .ends_with(secret_v2_key_suffixes::CERTIFICATE)
                                    .then(|| {
                                        cert_key.replace(
                                            secret_v2_key_suffixes::CERTIFICATE,
                                            secret_v2_key_suffixes::PRIVATE_KEY,
                                        )
                                    })?,
                            ))
                        })
                        .collect::<Result<_>>()?
                }
            }
            Entry::Vacant(_) if config.manage_ca => {
                update_ca_secret = true;
                let ca = CertificateAuthority::new_self_signed(config)?;
                info!(
                    secret = %secret_ref,
                    %ca,
                    %ca.not_after,
                    "Provisioning a new CA certificate, because it could not be found"
                );
                vec![ca]
            }
            Entry::Vacant(_) => {
                return CaNotFoundAndGenDisabledSnafu { secret: secret_ref }.fail();
            }
        };
        // Check whether CA should be rotated
        let newest_ca = certificate_authorities.iter().max_by_key(|ca| ca.not_after);
        if let (Some(cutoff_duration), Some(newest_ca)) =
            (config.rotate_if_ca_expires_before, newest_ca)
        {
            let cutoff = OffsetDateTime::now_utc() + cutoff_duration;
            let _span = info_span!(
                "ca_rotation",
                secret = %secret_ref,
                %cutoff,
                cutoff.duration = %cutoff_duration,
                %newest_ca,
                %newest_ca.not_after,
            )
            .entered();
            if newest_ca.not_after < cutoff {
                if config.manage_ca {
                    update_ca_secret = true;
                    info!(
                        "Provisioning a new CA certificate, because the old one will soon expire"
                    );
                    certificate_authorities.push(CertificateAuthority::new_self_signed(config)?);
                } else {
                    warn!("CA certificate will soon expire, please provision a new one");
                }
            } else {
                info!("CA is not close to expiring, will not initiate rotation");
            }
        }
        if update_ca_secret {
            if config.manage_ca {
                info!(secret = %secret_ref, "CA has been modified, saving");
                // Sort CAs by age to avoid spurious writes
                certificate_authorities.sort_by_key(|ca| ca.not_after);
                let mut occupied_ca_secret = ca_secret.or_insert(Secret::default);
                occupied_ca_secret.get_mut().data = Some(
                    certificate_authorities
                        .iter()
                        .enumerate()
                        .flat_map(|(i, ca)| {
                            [
                                ca.certificate
                                    .to_pem()
                                    .context(SerializeCertificateSnafu)
                                    .map(|cert| {
                                        (
                                            format!("{i}{}", secret_v2_key_suffixes::CERTIFICATE),
                                            ByteString(cert),
                                        )
                                    }),
                                ca.private_key
                                    .private_key_to_pem_pkcs8()
                                    .context(SerializeCertificateSnafu)
                                    .map(|key| {
                                        (
                                            format!("{i}{}", secret_v2_key_suffixes::PRIVATE_KEY),
                                            ByteString(key),
                                        )
                                    }),
                            ]
                        })
                        .collect::<Result<_>>()?,
                );
                occupied_ca_secret
                    .commit(&PostParams::default())
                    .await
                    .context(SaveCaCertificateSnafu { secret: secret_ref })?;
                ca_secret = Entry::Occupied(occupied_ca_secret);
            } else {
                return SaveRequestedButForbiddenSnafu.fail();
            }
        }

        let mut additional_trusted_certificates = vec![];
        for entry in additional_trust_roots {
            let certs = match entry {
                AdditionalTrustRoot::ConfigMap(config_map) => {
                    Self::read_extra_trust_roots_from_config_map(client, config_map).await?
                }
                AdditionalTrustRoot::Secret(secret) => {
                    Self::read_extra_trust_roots_from_secret(client, secret).await?
                }
            };
            additional_trusted_certificates.extend(certs);
        }

        Ok(Self {
            certificate_authorities,
            additional_trusted_certificates,
            source_secret: ca_secret
                .get()
                .map(|secret| secret.to_object_ref(()))
                .unwrap_or_else(|| secret_ref.into()),
        })
    }

    /// Read certificates from the given ConfigMap
    ///
    /// The keys are assumed to be filenames and their extensions denote the expected format of the
    /// certificate.
    async fn read_extra_trust_roots_from_config_map(
        client: &stackable_operator::client::Client,
        config_map_ref: &ConfigMapReference,
    ) -> Result<Vec<X509>> {
        let mut certificates = vec![];

        let config_map = client
            .get::<ConfigMap>(&config_map_ref.name, &config_map_ref.namespace)
            .await
            .context(FindExtraTrustRootSnafu {
                object: config_map_ref,
            })?;

        let config_map_data = config_map.data.unwrap_or_default();
        let config_map_binary_data = config_map.binary_data.unwrap_or_default();
        let data = config_map_data
            .iter()
            .map(|(key, value)| (key, value.as_bytes()))
            .chain(
                config_map_binary_data
                    .iter()
                    .map(|(key, ByteString(value))| (key, value.as_ref())),
            );
        for (key, value) in data {
            let certs = Self::deserialize_certificate(key, value, config_map_ref.into())?;
            info!(
                ?certs,
                %config_map_ref,
                %key,
                "adding certificates from additional trust root",
            );
            certificates.extend(certs);
        }

        Ok(certificates)
    }

    /// Read certificates from the given Secret
    ///
    /// The keys are assumed to be filenames and their extensions denote the expected format of the
    /// certificate.
    async fn read_extra_trust_roots_from_secret(
        client: &stackable_operator::client::Client,
        secret_ref: &SecretReference,
    ) -> Result<Vec<X509>> {
        let mut certificates = vec![];

        let secret = client
            .get::<Secret>(&secret_ref.name, &secret_ref.namespace)
            .await
            .context(FindExtraTrustRootSnafu { object: secret_ref })?;

        let secret_data = secret.data.unwrap_or_default();
        for (key, ByteString(value)) in &secret_data {
            let certs = Self::deserialize_certificate(key, value, secret_ref.into())?;
            info!(
                ?certs,
                %secret_ref,
                %key,
                "adding certificates from additional trust root",
            );
            certificates.extend(certs);
        }

        Ok(certificates)
    }

    /// Deserialize a certificate from the given value. The format is determined by the extension
    /// of the key.
    fn deserialize_certificate(
        key: &str,
        value: &[u8],
        object_ref: ObjectRef<DynamicObject>,
    ) -> Result<Vec<X509>> {
        let extension = Path::new(key).extension().and_then(OsStr::to_str);

        match extension {
            Some("crt") => X509::stack_from_pem(value),
            Some("der") => X509::from_der(value).map(|cert| vec![cert]),
            _ => {
                return UnsupportedCertificateFormatSnafu {
                    key,
                    object: object_ref,
                }
                .fail();
            }
        }
        .context(LoadCertificateSnafu {
            key,
            object: object_ref,
        })
    }

    /// Get an appropriate [`CertificateAuthority`] for signing a given certificate.
    pub fn find_certificate_authority_for_signing(
        &self,
        valid_until_at_least: OffsetDateTime,
    ) -> Result<&CertificateAuthority, GetCaError> {
        use get_ca_error::*;
        self.certificate_authorities
            .iter()
            .filter(|ca| ca.not_after > valid_until_at_least)
            // pick the oldest valid CA, since it will be trusted by the most peers
            .min_by_key(|ca| ca.not_after)
            .with_context(|| NoCaLivesLongEnoughSnafu {
                cutoff: valid_until_at_least,
                secret: self.source_secret.clone(),
            })
    }

    /// Get all active trust root certificates.
    pub fn trust_roots(&self) -> impl IntoIterator<Item = &X509> + '_ {
        self.certificate_authorities
            .iter()
            .map(|ca| &ca.certificate)
            .chain(&self.additional_trusted_certificates)
    }
}
