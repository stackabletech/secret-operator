use std::{collections::HashMap, path::PathBuf};

use openssl::x509::X509;
use snafu::{ResultExt, Snafu, ensure};
use stackable_secret_operator_utils::pkcs12::pkcs12_truststore;

use crate::{cert_ext::CertExt, cli::GeneratePkcs12TruststoreArguments};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display(
        "the list of certificate sources can not be empty. provide at least one --pem or --pkcs12"
    ))]
    NoCertificateSources,

    #[snafu(display("failed to read certifcate source at {path}", path = path.display()))]
    ReadCertificate {
        source: crate::cli::CertInputError,
        path: PathBuf,
    },

    #[snafu(display("failed to retrieve certificate digest"))]
    RetrieveCertificateDigest { source: crate::cert_ext::Error },

    #[snafu(display("failed to retrieve certificate serial number encoded as hex"))]
    RetrieveCertificateSerial { source: crate::cert_ext::Error },

    #[snafu(display("failed to create truststore"))]
    CreateTruststore {
        source: stackable_secret_operator_utils::pkcs12::TlsToPkcs12Error,
    },

    #[snafu(display("failed to write truststore contents to file at {path}", path = path.display()))]
    WriteTruststoreFile {
        source: std::io::Error,
        path: PathBuf,
    },
}

pub fn generate_truststore(args: GeneratePkcs12TruststoreArguments) -> Result<(), Error> {
    let certificate_sources = args.certificate_sources();
    ensure!(!certificate_sources.is_empty(), NoCertificateSourcesSnafu);

    let certificate_sources = certificate_sources
        .iter()
        .map(|source| {
            let certificates_list = source.from_file().context(ReadCertificateSnafu {
                path: source.path(),
            })?;

            Ok((source, certificates_list))
        })
        .collect::<Result<Vec<_>, Error>>()?;

    let mut certificates = HashMap::<Vec<u8>, X509>::new();
    for (source, certificates_list) in certificate_sources.into_iter() {
        tracing::info!(?source, "Importing certificates");

        for certificate in certificates_list {
            let sha256_digest = certificate
                .sha256_digest()
                .context(RetrieveCertificateDigestSnafu)?;

            let new_serial = certificate
                .serial_as_hex()
                .context(RetrieveCertificateSerialSnafu)?;

            // Trying to stick to https://opentelemetry.io/docs/specs/semconv/registry/attributes/tls/#tls-attributes
            // for the tracing statements. Converting `Asn1TimeRef` to a ISO 8601 timestamp really
            // sucks, so we omitted that.
            if let Some(existing) = certificates.get(&*sha256_digest) {
                let existing_serial = existing
                    .serial_as_hex()
                    .context(RetrieveCertificateSerialSnafu)?;

                tracing::warn!(
                    hash.sha256 = hex::encode(sha256_digest).to_uppercase(),
                    existing.not_before = ?existing.not_before(),
                    existing.not_after = ?existing.not_after(),
                    existing.subject = ?existing.subject_name(),
                    existing.issuer = ?existing.issuer_name(),
                    existing.serial = ?existing_serial,
                    new.not_before = ?certificate.not_before(),
                    new.not_after = ?certificate.not_after(),
                    new.subject = ?certificate.subject_name(),
                    new.issuer = ?certificate.issuer_name(),
                    new.serial = ?new_serial,
                    ?source,
                    "Skipped certificate as a cert with the same SHA256 hash was already added",
                );
            } else {
                tracing::info!(
                    subject = ?certificate.subject_name(),
                    issuer = ?certificate.issuer_name(),
                    not_before = ?certificate.not_before(),
                    not_after = ?certificate.not_after(),
                    serial = ?new_serial,
                    ?source,
                    "Added certificate"
                );

                certificates.insert(sha256_digest.to_vec(), certificate);
            }
        }
    }

    let pkcs12_truststore_bytes =
        pkcs12_truststore(certificates.values().map(|c| &**c), &args.out_password)
            .context(CreateTruststoreSnafu)?;

    std::fs::write(&args.out, &pkcs12_truststore_bytes)
        .context(WriteTruststoreFileSnafu { path: args.out })
}
