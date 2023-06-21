use openssl::{
    error::ErrorStack as OpensslError, pkcs12::Pkcs12, pkey::PKey, stack::Stack, x509::X509,
};
use snafu::{ResultExt, Snafu};

use crate::format::utils::split_pem_certificates;

use super::{
    well_known::{Tls, TlsPkcs12},
    SecretFormat, WellKnownSecretData,
};

pub fn convert(
    from: WellKnownSecretData,
    to: SecretFormat,
) -> Result<WellKnownSecretData, ConvertError> {
    match (from, to) {
        // Converting into the current format is always a no-op
        (from, to) if SecretFormat::from(&from) == to => Ok(from),

        (WellKnownSecretData::Tls(pem), SecretFormat::TlsPkcs12) => {
            Ok(WellKnownSecretData::TlsPkcs12(convert_tls_to_pkcs12(pem)?))
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

pub fn convert_tls_to_pkcs12(pem: Tls) -> Result<TlsPkcs12, TlsToPkcs12Error> {
    use tls_to_pkcs12_error::*;
    let cert = X509::from_pem(&pem.certificate_pem).context(LoadCertSnafu)?;
    let key = PKey::private_key_from_pem(&pem.key_pem).context(LoadKeySnafu)?;

    let mut ca_stack = Stack::<X509>::new().context(LoadCaSnafu)?;
    for ca in split_pem_certificates(&pem.ca_pem) {
        X509::from_pem(ca)
            .and_then(|ca| ca_stack.push(ca))
            .context(LoadCertSnafu)?;
    }

    let mut pkcs_builder = Pkcs12::builder();

    Ok(TlsPkcs12 {
        truststore: pkcs_builder
            .ca(ca_stack)
            .build2("")
            .and_then(|store| store.to_der())
            .context(BuildTruststoreSnafu)?,
        keystore: pkcs_builder
            .cert(&cert)
            .pkey(&key)
            .build2("")
            .and_then(|store| store.to_der())
            .context(BuildKeystoreSnafu)?,
    })
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum TlsToPkcs12Error {
    LoadCert { source: OpensslError },
    LoadKey { source: OpensslError },
    LoadCa { source: OpensslError },
    BuildKeystore { source: OpensslError },
    BuildTruststore { source: OpensslError },
}
