use std::{fs, path::PathBuf};

use clap::{Parser, Subcommand};
use openssl::x509::X509;
use snafu::{ResultExt, ensure_whatever};
use stackable_telemetry::tracing::TelemetryOptions;

use crate::parsers::{parse_pem_contents, parse_pkcs12_file_workaround};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: CliCommand,

    #[command(flatten, next_help_heading = "Tracing options")]
    pub telemetry: TelemetryOptions,
}

#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// Generate PKCS12 truststore files from PEM or PKCS12 files
    GeneratePkcs12Truststore(GeneratePkcs12),
}

#[derive(Parser, Debug)]
pub struct GeneratePkcs12 {
    /// The path to output the resulting PKCS12 to
    #[arg(long)]
    pub out: PathBuf,

    /// The password used to encrypt the outputted PKCS12 truststore. Defaults to an empty string.
    #[arg(long, default_value = "")]
    pub out_password: String,

    /// List of PEM certificate(s)
    #[arg(long = "pem")]
    pub pems: Vec<PathBuf>,

    /// List of PKCS12 truststore(s)
    ///
    /// You can either use `truststore.p12` (which uses an empty password by default), or specify
    /// the password using `truststore.p12:changeit`.
    #[arg(long = "pkcs12", value_parser = parse_cli_pkcs12_source)]
    pub pkcs12s: Vec<Pkcs12Source>,
}

#[derive(Debug)]
pub enum CertInput {
    Pem(PathBuf),
    Pkcs12(Pkcs12Source),
}

#[derive(Clone, Debug)]
pub struct Pkcs12Source {
    path: PathBuf,
    password: String,
}

fn parse_cli_pkcs12_source(cli_argument: &str) -> Result<Pkcs12Source, String> {
    let mut parts = cli_argument.splitn(2, ':');
    let path = parts
        .next()
        .ok_or_else(|| "missing path part".to_string())?;
    let password = parts.next().unwrap_or("").to_string();

    Ok(Pkcs12Source {
        path: PathBuf::from(path),
        password,
    })
}

impl GeneratePkcs12 {
    pub fn certificate_sources(&self) -> Vec<CertInput> {
        let pems = self.pems.iter().cloned().map(CertInput::Pem);
        let pkcs12s = self.pkcs12s.iter().cloned().map(CertInput::Pkcs12);
        pems.chain(pkcs12s).collect()
    }
}

impl CertInput {
    pub fn read(&self) -> Result<Vec<X509>, snafu::Whatever> {
        let read_file_fn = |path| {
            fs::read(path).with_whatever_context(|_| format!("failed to read from file {self:?}"))
        };

        match self {
            CertInput::Pem(path) => {
                let file_contents = read_file_fn(path)?;

                let certs = parse_pem_contents(&file_contents).with_whatever_context(|_| {
                    format!(
                        "failed to parse PEM contents from {path:?}",
                        path = self.path()
                    )
                })?;
                ensure_whatever!(
                    !certs.is_empty(),
                    "The PEM file at {path:?} contained no certificates",
                );

                Ok(certs)
            }
            CertInput::Pkcs12(Pkcs12Source { path, password }) => {
                let file_contents = read_file_fn(path)?;

                parse_pkcs12_file_workaround(&file_contents, password)
            }
        }
    }

    pub fn path(&self) -> &PathBuf {
        match self {
            CertInput::Pem(path) => path,
            CertInput::Pkcs12(Pkcs12Source { path, .. }) => path,
        }
    }
}
