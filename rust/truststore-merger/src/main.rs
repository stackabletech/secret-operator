use std::{collections::HashMap, fs};

use anyhow::{Context, ensure};
use clap::Parser;
use cli_args::Cli;
use openssl::x509::X509;
use stackable_secret_operator_utils::pkcs12::pkcs12_truststore;
use tracing::{info, level_filters::LevelFilter, warn};

mod cli_args;

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
        for certificate in certificates_list {
            let serial_bn = certificate
                .serial_number()
                .to_bn()
                .context("failed to get certificate serial number as BigNumber")?;
            let serial = serial_bn.to_vec();
            if let Some(existing) = certificates.get(&serial) {
                warn!(
                    serial = ?serial_bn.to_hex_str(),
                    ?source,
                    existing.not_after = ?existing.not_after(),
                    existing.subject = ?existing.subject_name(),
                    new.not_after = ?certificate.not_after(),
                    new.subject = ?certificate.subject_name(),
                    "Skipped certificate as it was already added",
                );
            } else {
                info!(
                    serial = ?serial_bn.to_hex_str(),
                    not_after = ?certificate.not_after(),
                    subject = ?certificate.subject_name(),
                    ?source,
                    "Added certificate"
                );
                certificates.insert(serial, certificate);
            }
        }
    }

    let pkcs12_truststore_bytes = pkcs12_truststore(certificates.values().map(|c| &**c), "")
        .context("failed to create pkcs12 truststore from certificates")?;
    fs::write(&cli.out, &pkcs12_truststore_bytes).with_context(|| {
        format!(
            "failed to write to output pkcs12 truststore at {:?}",
            cli.out
        )
    })?;

    Ok(())
}
