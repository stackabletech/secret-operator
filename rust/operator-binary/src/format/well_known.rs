use super::{convert, ConvertError, SecretFiles};
use serde::Deserialize;
use snafu::{OptionExt, Snafu};
use strum::EnumDiscriminants;

const FILE_PEM_CERT_CERT: &str = "tls.crt";
const FILE_PEM_CERT_KEY: &str = "tls.key";
const FILE_PEM_CERT_CA: &str = "ca.crt";

const FILE_PKCS12_CERT_KEYSTORE: &str = "keystore.p12";
const FILE_PKCS12_CERT_TRUSTSTORE: &str = "truststore.p12";

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
    pub fn into_files(self) -> SecretFiles {
        match self {
            WellKnownSecretData::TlsPem(TlsPem {
                certificate_pem,
                key_pem,
                ca_pem,
            }) => [
                (FILE_PEM_CERT_CERT.to_string(), certificate_pem),
                (FILE_PEM_CERT_KEY.to_string(), key_pem),
                (FILE_PEM_CERT_CA.to_string(), ca_pem),
            ]
            .into(),
            WellKnownSecretData::TlsPkcs12(TlsPkcs12 {
                keystore,
                truststore,
            }) => [
                (FILE_PKCS12_CERT_KEYSTORE.to_string(), keystore),
                (FILE_PKCS12_CERT_TRUSTSTORE.to_string(), truststore),
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

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum FromFilesError {
    #[snafu(display("could not identify a secret format containing the files {files:?}"))]
    UnknownFormat { files: Vec<String> },

    #[snafu(display("unable to parse as {format:?}: missing required file {file:?}"))]
    MissingRequiredFile { format: SecretFormat, file: String },
}
