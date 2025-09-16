use openssl::{pkcs12::Pkcs12, pkey::PKey, stack::Stack, x509::X509};
use snafu::{ResultExt, Snafu};
use stackable_secret_operator_utils::{
    pem::split_pem_certificates,
    pkcs12::{TlsToPkcs12Error, pkcs12_truststore},
};

use super::{
    SecretFormat, WellKnownSecretData,
    well_known::{CompatibilityOptions, TlsPem, TlsPkcs12},
};

pub fn convert(
    from: WellKnownSecretData,
    to: SecretFormat,
    compat: CompatibilityOptions,
) -> Result<WellKnownSecretData, ConvertError> {
    match (from, to) {
        // Converting into the current format is always a no-op
        (from, to) if SecretFormat::from(&from) == to => Ok(from),

        (WellKnownSecretData::TlsPem(pem), SecretFormat::TlsPkcs12) => {
            Ok(WellKnownSecretData::TlsPkcs12(convert_tls_to_pkcs12(
                pem,
                compat.tls_pkcs12_password.as_deref().unwrap_or_default(),
            )?))
        }

        (from, to) => NoValidConversionSnafu { from, to }.fail(),
    }
}

#[derive(Snafu, Debug)]
pub enum ConvertError {
    #[snafu(display("no conversion defined from {from:?} to {to:?}"))]
    NoValidConversion {
        from: SecretFormat,
        to: SecretFormat,
    },

    #[snafu(
        display("failed to convert from PEM certificate to PKCS#12"),
        context(false)
    )]
    TlsToPkcs12 { source: TlsToPkcs12Error },
}

pub fn convert_tls_to_pkcs12(
    pem: TlsPem,
    p12_password: &str,
) -> Result<TlsPkcs12, TlsToPkcs12Error> {
    use stackable_secret_operator_utils::pkcs12::tls_to_pkcs12_error::*;
    let cert = pem
        .certificate_pem
        .map(|cert| X509::from_pem(&cert).context(LoadCertSnafu))
        .transpose()?;
    let key = pem
        .key_pem
        .map(|key| PKey::private_key_from_pem(&key).context(LoadKeySnafu))
        .transpose()?;

    let mut ca_stack = Stack::<X509>::new().context(LoadCaSnafu)?;
    for ca in split_pem_certificates(&pem.ca_pem) {
        X509::from_pem(ca)
            .and_then(|ca| ca_stack.push(ca))
            .context(LoadCertSnafu)?;
    }

    Ok(TlsPkcs12 {
        truststore: pkcs12_truststore(&ca_stack, p12_password)?,
        keystore: cert
            .zip(key)
            .map(|(cert, key)| {
                Pkcs12::builder()
                    .ca(ca_stack)
                    .cert(&cert)
                    .pkey(&key)
                    .build2(p12_password)
                    .and_then(|store| store.to_der())
                    .context(BuildKeystoreSnafu)
            })
            .transpose()?,
    })
}
