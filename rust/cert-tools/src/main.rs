use std::{collections::HashMap, fs};

use cert_ext::CertExt;
use clap::Parser;
use cli_args::{Cli, CliCommand, GeneratePkcs12};
use openssl::x509::X509;
use snafu::{ResultExt, ensure_whatever};
use stackable_secret_operator_utils::pkcs12::pkcs12_truststore;
use stackable_telemetry::Tracing;
use tracing::{info, warn};

mod cert_ext;
mod cli_args;
mod parsers;

#[snafu::report]
pub fn main() -> Result<(), snafu::Whatever> {
    let cli = Cli::parse();

    // Use `CONSOLE_LOG_LEVEL` to modify the console log level
    let _tracing_guard = Tracing::pre_configured("cert-tools", cli.telemetry)
        .init()
        .whatever_context("failed to initialize tracing")?;

    match cli.command {
        CliCommand::GeneratePkcs12Truststore(cli_args) => generate_pkcs12_truststore(cli_args)?,
    }

    Ok(())
}

fn generate_pkcs12_truststore(cli_args: GeneratePkcs12) -> Result<(), snafu::Whatever> {
    let certificate_sources = cli_args.certificate_sources();
    ensure_whatever!(
        !certificate_sources.is_empty(),
        "The list of certificate sources can not be empty. Please provide at least on --pem or --pkcs12."
    );
    let certificate_sources = certificate_sources
        .iter()
        .map(|source| {
            let certificate = source.read().with_whatever_context(|_| {
                format!(
                    "failed to read certificate source {path:?}",
                    path = source.path()
                )
            })?;
            Ok((source, certificate))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut certificates = HashMap::<Vec<u8>, X509>::new();
    for (source, certificates_list) in certificate_sources.into_iter() {
        info!(?source, "Importing certificates");

        for certificate in certificates_list {
            let sha256 = certificate.sha256_digest()?;

            // Trying to stick to https://opentelemetry.io/docs/specs/semconv/registry/attributes/tls/#tls-attributes
            // Converting `Asn1TimeRef` to a ISO 8601 timestamp really sucks, so we omitted that.
            if let Some(existing) = certificates.get(&*sha256) {
                warn!(
                    ?source,
                    hash.sha256 = hex::encode(sha256).to_uppercase(),
                    existing.not_before = ?existing.not_before(),
                    existing.not_after = ?existing.not_after(),
                    existing.subject = ?existing.subject_name(),
                    existing.issuer = ?existing.issuer_name(),
                    existing.serial = ?existing.serial_as_hex()?,
                    new.not_before = ?certificate.not_before(),
                    new.not_after = ?certificate.not_after(),
                    new.subject = ?certificate.subject_name(),
                    new.issuer = ?certificate.issuer_name(),
                    new.serial = ?existing.serial_as_hex()?,
                    "Skipped certificate as a cert with the same SHA256 hash was already added",
                );
            } else {
                info!(
                    subject = ?certificate.subject_name(),
                    issuer = ?certificate.issuer_name(),
                    not_before = ?certificate.not_before(),
                    not_after = ?certificate.not_after(),
                    serial = ?certificate.serial_as_hex()?,
                    ?source,
                    "Added certificate"
                );
                certificates.insert(sha256.to_vec(), certificate);
            }
        }
    }

    let pkcs12_truststore_bytes =
        pkcs12_truststore(certificates.values().map(|c| &**c), &cli_args.out_password)
            .whatever_context("failed to create PKCS12 truststore from certificates")?;
    fs::write(&cli_args.out, &pkcs12_truststore_bytes).with_whatever_context(|_| {
        format!(
            "failed to write to output PKCS12 truststore at {:?}",
            cli_args.out
        )
    })?;

    Ok(())
}
