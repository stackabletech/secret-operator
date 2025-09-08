use std::{collections::HashMap, fs};

use anyhow::{Context, ensure};
use cert_ext::CertExt;
use clap::Parser;
use cli_args::Cli;
use openssl::x509::X509;
use stackable_secret_operator_utils::pkcs12::pkcs12_truststore;
use tracing::{info, level_filters::LevelFilter, warn};

mod cert_ext;
mod cli_args;
mod parsers;

pub fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env()?;
    tracing_subscriber::fmt()
        // Short running tool does not need any complex output
        .with_target(false)
        .without_time()
        .with_env_filter(filter)
        .init();

    let cli = Cli::parse();

    let certificate_sources = cli.certificate_sources();
    ensure!(
        !certificate_sources.is_empty(),
        "The list of certificate sources can not be empty. Please provide at least on --pem or --pkcs12."
    );
    let certificate_sources = certificate_sources
        .iter()
        .map(|source| {
            let certificate = source.read().with_context(|| {
                format!(
                    "failed to read certificate source {path:?}",
                    path = source.path()
                )
            })?;
            Ok((source, certificate))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut certificates = HashMap::<Vec<u8>, X509>::new();
    for (source, certificates_list) in certificate_sources.into_iter() {
        info!(?source, "Importing certificates");

        for certificate in certificates_list {
            let sha256 = certificate.sha256_digest()?;

            if let Some(existing) = certificates.get(&*sha256) {
                warn!(
                    ?source,
                    sha25 = hex::encode(sha256),
                    existing.not_before = ?existing.not_before(),
                    existing.not_after = ?existing.not_after(),
                    existing.subject = ?existing.subject_name(),
                    existing.serial = ?existing.serial_as_hex()?,
                    new.not_before = ?certificate.not_before(),
                    new.not_after = ?certificate.not_after(),
                    new.subject = ?certificate.subject_name(),
                    new.serial = ?existing.serial_as_hex()?,
                    "Skipped certificate as a cert with the same SHA256 hash was already added",
                );
            } else {
                info!(
                    subject = ?certificate.subject_name(),
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
        pkcs12_truststore(certificates.values().map(|c| &**c), &cli.out_password)
            .context("failed to create PKCS12 truststore from certificates")?;
    fs::write(&cli.out, &pkcs12_truststore_bytes).with_context(|| {
        format!(
            "failed to write to output PKCS12 truststore at {:?}",
            cli.out
        )
    })?;

    Ok(())
}
