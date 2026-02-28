use serde::{Deserialize, Serialize};
use snafu::{OptionExt, Snafu};
use stackable_operator::schemars::{self, JsonSchema};
use strum::EnumDiscriminants;

use super::{ConvertError, SecretFiles, convert};

const FILE_PEM_CERT_CERT: &str = "tls.crt";
const FILE_PEM_CERT_KEY: &str = "tls.key";
pub const FILE_PEM_CERT_CA: &str = "ca.crt";

const FILE_PKCS12_CERT_KEYSTORE: &str = "keystore.p12";
const FILE_PKCS12_CERT_TRUSTSTORE: &str = "truststore.p12";

const FILE_KERBEROS_KEYTAB_KEYTAB: &str = "keytab";
const FILE_KERBEROS_KEYTAB_KRB5_CONF: &str = "krb5.conf";

#[derive(Debug)]
pub struct TlsPem {
    pub certificate_pem: Option<Vec<u8>>,
    pub key_pem: Option<Vec<u8>>,
    pub ca_pem: Vec<u8>,
}

#[derive(Debug)]
pub struct TlsPkcs12 {
    pub keystore: Option<Vec<u8>>,
    pub truststore: Vec<u8>,
}

#[derive(Debug)]
pub struct Kerberos {
    pub keytab: Vec<u8>,
    pub krb5_conf: Vec<u8>,
}

#[derive(Debug, EnumDiscriminants)]
#[strum_discriminants(
    name(SecretFormat),
    derive(Serialize, Deserialize, JsonSchema),
    serde(rename_all = "kebab-case")
)]
pub enum WellKnownSecretData {
    TlsPem(TlsPem),
    TlsPkcs12(TlsPkcs12),
    Kerberos(Kerberos),
}

impl WellKnownSecretData {
    pub fn into_files(self, names: NamingOptions) -> SecretFiles {
        match self {
            WellKnownSecretData::TlsPem(TlsPem {
                certificate_pem,
                key_pem,
                ca_pem,
            }) => [
                Some(names.tls_pem_cert_name).zip(certificate_pem),
                Some(names.tls_pem_key_name).zip(key_pem),
                Some((names.tls_pem_ca_name, ca_pem)),
            ]
            .into_iter()
            .flatten()
            .collect(),
            WellKnownSecretData::TlsPkcs12(TlsPkcs12 {
                keystore,
                truststore,
            }) => [
                Some(names.tls_pkcs12_keystore_name).zip(keystore),
                Some((names.tls_pkcs12_truststore_name, truststore)),
            ]
            .into_iter()
            .flatten()
            .collect(),
            WellKnownSecretData::Kerberos(Kerberos { keytab, krb5_conf }) => [
                (FILE_KERBEROS_KEYTAB_KEYTAB.to_string(), keytab),
                (FILE_KERBEROS_KEYTAB_KRB5_CONF.to_string(), krb5_conf),
            ]
            .into(),
        }
    }

    pub fn from_files(mut files: SecretFiles) -> Result<WellKnownSecretData, FromFilesError> {
        let mut take_file = |format, file| {
            files
                .remove(file)
                .context(from_files_error::MissingRequiredFileSnafu { format, file })
        };

        if let Ok(certificate_pem) = take_file(SecretFormat::TlsPem, FILE_PEM_CERT_CERT) {
            let mut take_file = |file| take_file(SecretFormat::TlsPem, file);
            Ok(WellKnownSecretData::TlsPem(TlsPem {
                certificate_pem: Some(certificate_pem),
                key_pem: Some(take_file(FILE_PEM_CERT_KEY)?),
                ca_pem: take_file(FILE_PEM_CERT_CA)?,
            }))
        } else if let Ok(keystore) = take_file(SecretFormat::TlsPkcs12, FILE_PKCS12_CERT_KEYSTORE) {
            Ok(WellKnownSecretData::TlsPkcs12(TlsPkcs12 {
                keystore: Some(keystore),
                truststore: take_file(SecretFormat::TlsPkcs12, FILE_PKCS12_CERT_TRUSTSTORE)?,
            }))
        } else if let Ok(keytab) = take_file(SecretFormat::Kerberos, FILE_KERBEROS_KEYTAB_KEYTAB) {
            Ok(WellKnownSecretData::Kerberos(Kerberos {
                keytab,
                krb5_conf: take_file(SecretFormat::Kerberos, FILE_KERBEROS_KEYTAB_KRB5_CONF)?,
            }))
        } else {
            from_files_error::UnknownFormatSnafu {
                files: files.into_keys().collect::<Vec<_>>(),
            }
            .fail()
        }
    }

    pub fn convert_to(
        self,
        to: SecretFormat,
        compat: CompatibilityOptions,
    ) -> Result<Self, ConvertError> {
        convert::convert(self, to, compat)
    }
}

/// Options that some (legacy) applications require to ensure compatibility.
///
/// The expectation is that this will be unset the vast majority of the time.
#[derive(Debug, Default, Deserialize)]
pub struct CompatibilityOptions {
    /// The password used to encrypt the TLS PKCS#12 keystore
    ///
    /// Required for some applications that misbehave with blank keystore passwords (such as Hadoop).
    /// Has no effect if `format` is not `tls-pkcs12`.
    #[serde(
        rename = "secrets.stackable.tech/format.compatibility.tls-pkcs12.password",
        default
    )]
    pub tls_pkcs12_password: Option<String>,
}

/// Options to customize the well-known format file names.
///
/// The fields will either contain the default value or the custom user-provided one. This is also
/// the reason why the fields are not wrapped in [`Option`].
#[derive(Debug, Deserialize)]
pub struct NamingOptions {
    /// An alternative name used for the TLS PKCS#12 keystore file.
    ///
    /// Has no effect if the `format` is not `tls-pkcs12`.
    #[serde(
        rename = "secrets.stackable.tech/format.tls-pkcs12.keystore-name",
        default = "default_pkcs12_keystore_name"
    )]
    pub tls_pkcs12_keystore_name: String,

    /// An alternative name used for the TLS PKCS#12 keystore file.
    ///
    /// Has no effect if the `format` is not `tls-pkcs12`.
    #[serde(
        rename = "secrets.stackable.tech/format.tls-pkcs12.truststore-name",
        default = "default_pkcs12_truststore_name"
    )]
    pub tls_pkcs12_truststore_name: String,

    /// An alternative name used for the TLS PEM certificate.
    ///
    /// Has no effect if the `format` is not `tls-pem`.
    #[serde(
        rename = "secrets.stackable.tech/format.tls-pem.cert-name",
        default = "default_tls_pem_cert_name"
    )]
    pub tls_pem_cert_name: String,

    /// An alternative name used for the TLS PEM certificate key.
    ///
    /// Has no effect if the `format` is not `tls-pem`.
    #[serde(
        rename = "secrets.stackable.tech/format.tls-pem.key-name",
        default = "default_tls_pem_key_name"
    )]
    pub tls_pem_key_name: String,

    /// An alternative name used for the TLS PEM certificate authority.
    ///
    /// Has no effect if the `format` is not `tls-pem`.
    #[serde(
        rename = "secrets.stackable.tech/format.tls-pem.ca-name",
        default = "default_tls_pem_ca_name"
    )]
    pub tls_pem_ca_name: String,
}

impl Default for NamingOptions {
    fn default() -> Self {
        Self {
            tls_pkcs12_keystore_name: default_pkcs12_keystore_name(),
            tls_pkcs12_truststore_name: default_pkcs12_truststore_name(),
            tls_pem_cert_name: default_tls_pem_cert_name(),
            tls_pem_key_name: default_tls_pem_key_name(),
            tls_pem_ca_name: default_tls_pem_ca_name(),
        }
    }
}

fn default_pkcs12_keystore_name() -> String {
    FILE_PKCS12_CERT_KEYSTORE.to_owned()
}

fn default_pkcs12_truststore_name() -> String {
    FILE_PKCS12_CERT_TRUSTSTORE.to_owned()
}

fn default_tls_pem_cert_name() -> String {
    FILE_PEM_CERT_CERT.to_owned()
}

fn default_tls_pem_key_name() -> String {
    FILE_PEM_CERT_KEY.to_owned()
}

fn default_tls_pem_ca_name() -> String {
    FILE_PEM_CERT_CA.to_owned()
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum FromFilesError {
    #[snafu(display("could not identify a secret format containing the files {files:?}"))]
    UnknownFormat { files: Vec<String> },

    #[snafu(display("unable to parse as {format:?}: missing required file {file:?}"))]
    MissingRequiredFile { format: SecretFormat, file: String },
}
