use openssl::{
    error::ErrorStack as OpensslError,
    pkcs12::Pkcs12,
    pkey::PKey,
    stack::Stack,
    x509::{X509, X509Ref},
};
use snafu::{OptionExt, ResultExt, Snafu};

use super::{
    SecretFormat, WellKnownSecretData,
    well_known::{CompatibilityOptions, TlsPem, TlsPkcs12},
};
use crate::format::utils::split_pem_certificates;

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
    use tls_to_pkcs12_error::*;
    let cert = X509::from_pem(&pem.certificate_pem).context(LoadCertSnafu)?;
    let key = PKey::private_key_from_pem(&pem.key_pem).context(LoadKeySnafu)?;

    let mut ca_stack = Stack::<X509>::new().context(LoadCaSnafu)?;
    for ca in split_pem_certificates(&pem.ca_pem) {
        X509::from_pem(ca)
            .and_then(|ca| ca_stack.push(ca))
            .context(LoadCertSnafu)?;
    }

    Ok(TlsPkcs12 {
        truststore: pkcs12_truststore(&ca_stack, p12_password)?,
        keystore: Pkcs12::builder()
            .ca(ca_stack)
            .cert(&cert)
            .pkey(&key)
            .build2(p12_password)
            .and_then(|store| store.to_der())
            .context(BuildKeystoreSnafu)?,
    })
}

fn bmp_string(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0]) // null-termination character
        .flat_map(u16::to_be_bytes)
        .collect()
}

fn pkcs12_truststore<'a>(
    ca_list: impl IntoIterator<Item = &'a X509Ref>,
    p12_password: &str,
) -> Result<Vec<u8>, TlsToPkcs12Error> {
    // We can't use OpenSSL's `Pkcs12`, since it doesn't let us add new attributes to the SafeBags being created,
    // and Java refuses to trust CA bags without the `java_trusted_ca_oid` attribute set.
    // OpenSSL's current master branch contains the `PKCS12_create_ex2` function
    // (https://www.openssl.org/docs/manmaster/man3/PKCS12_create_ex.html), but it is not currently in
    // OpenSSL 3.1 (as of 3.1.1), and it is not wrapped by rust-openssl.

    // Required for Java to trust the certificate, from
    // https://github.com/openjdk/jdk/blob/990e3a700dce3441bd9506ca571c1790e57849a9/src/java.base/share/classes/sun/security/util/KnownOIDs.java#L414-L415
    let java_oracle_trusted_key_usage_oid =
        yasna::models::ObjectIdentifier::from_slice(&[2, 16, 840, 1, 113894, 746875, 1, 1]);

    let mut truststore_bags = Vec::new();
    for ca in ca_list {
        truststore_bags.push(p12::SafeBag {
            bag: p12::SafeBagKind::CertBag(p12::CertBag::X509(
                ca.to_der()
                    .context(tls_to_pkcs12_error::SerializeCaForTruststoreSnafu)?,
            )),
            attributes: vec![p12::PKCS12Attribute::Other(p12::OtherAttribute {
                oid: java_oracle_trusted_key_usage_oid.clone(),
                data: Vec::new(),
            })],
        });
    }
    let password_as_bmp_string = bmp_string(p12_password);
    let encrypted_data = p12::ContentInfo::EncryptedData(
        p12::EncryptedData::from_safe_bags(&truststore_bags[..], &password_as_bmp_string)
            .context(tls_to_pkcs12_error::EncryptDataForTruststoreSnafu)?,
    );
    let truststore_data = yasna::construct_der(|w| {
        w.write_sequence_of(|w| {
            encrypted_data.write(w.next());
        });
    });
    Ok(p12::PFX {
        version: 3,
        mac_data: Some(p12::MacData::new(&truststore_data, &password_as_bmp_string)),
        auth_safe: p12::ContentInfo::Data(truststore_data),
    }
    .to_der())
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum TlsToPkcs12Error {
    #[snafu(display("failed to load certificate"))]
    LoadCert { source: OpensslError },

    #[snafu(display("failed to load private key"))]
    LoadKey { source: OpensslError },

    #[snafu(display("failed to load CA certificate"))]
    LoadCa { source: OpensslError },

    #[snafu(display("failed to build keystore"))]
    BuildKeystore { source: OpensslError },

    #[snafu(display("failed to serialize CA certificate for truststore"))]
    SerializeCaForTruststore { source: OpensslError },

    #[snafu(display("failed to encrypt data for truststore"))]
    EncryptDataForTruststore,
}
