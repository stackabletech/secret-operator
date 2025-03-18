use serde::Deserialize;
use snafu::{OptionExt, Snafu};
use strum::EnumDiscriminants;

use super::{convert, ConvertError, SecretFiles};

pub const FILE_PEM_CERT_CERT: &str = "tls.crt";
pub const FILE_PEM_CERT_KEY: &str = "tls.key";
pub const FILE_PEM_CERT_CA: &str = "ca.crt";

pub const FILE_PKCS12_CERT_KEYSTORE: &str = "keystore.p12";
pub const FILE_PKCS12_CERT_TRUSTSTORE: &str = "truststore.p12";

const FILE_KERBEROS_KEYTAB_KEYTAB: &str = "keytab";
const FILE_KERBEROS_KEYTAB_KRB5_CONF: &str = "krb5.conf";

#[derive(Debug)]
pub struct TlsPem {
    pub certificate_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
    pub ca_pem: Vec<u8>,
}

#[derive(Debug)]
pub struct TlsPkcs12 {
    pub keystore: Vec<u8>,
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
    derive(Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum WellKnownSecretData {
    TlsPem(TlsPem),
    TlsPkcs12(TlsPkcs12),
    Kerberos(Kerberos),
}

impl WellKnownSecretData {
    pub fn into_files(self, names: &NamingOptions) -> SecretFiles {
        match self {
            WellKnownSecretData::TlsPem(TlsPem {
                certificate_pem,
                key_pem,
                ca_pem,
            }) => [
                (names.tls_pem_cert_name.to_string(), certificate_pem),
                (names.tls_pem_key_name.to_string(), key_pem),
                (names.tls_pem_ca_name.to_string(), ca_pem),
            ]
            .into(),
            WellKnownSecretData::TlsPkcs12(TlsPkcs12 {
                keystore,
                truststore,
            }) => [
                (names.tls_pkcs12_keystore_name.to_string(), keystore),
                (names.tls_pkcs12_truststore_name.to_string(), truststore),
            ]
            .into(),
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
                certificate_pem,
                key_pem: take_file(FILE_PEM_CERT_KEY)?,
                ca_pem: take_file(FILE_PEM_CERT_CA)?,
            }))
        } else if let Ok(keystore) = take_file(SecretFormat::TlsPkcs12, FILE_PKCS12_CERT_KEYSTORE) {
            Ok(WellKnownSecretData::TlsPkcs12(TlsPkcs12 {
                keystore,
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
        compat: &CompatibilityOptions,
    ) -> Result<Self, ConvertError> {
        convert::convert(self, to, compat)
    }
}

/// Options that some (legacy) applications require to ensure compatibility.
///
/// The expectation is that this will be unset the vast majority of the time.
#[derive(Default)]
pub struct CompatibilityOptions {
    pub tls_pkcs12_password: Option<String>,
}

/// Options to customize the well-known format file names.
///
/// The fields will either contain the default value or the custom user-provided one. This is also
/// the reason why the fields are not wrapped in [`Option`].
pub struct NamingOptions {
    pub tls_pkcs12_keystore_name: String,
    pub tls_pkcs12_truststore_name: String,
    pub tls_pem_cert_name: String,
    pub tls_pem_key_name: String,
    pub tls_pem_ca_name: String,
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum FromFilesError {
    #[snafu(display("could not identify a secret format containing the files {files:?}"))]
    UnknownFormat { files: Vec<String> },

    #[snafu(display("unable to parse as {format:?}: missing required file {file:?}"))]
    MissingRequiredFile { format: SecretFormat, file: String },
}
