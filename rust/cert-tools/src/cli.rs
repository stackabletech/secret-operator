use std::{fs, path::PathBuf, str::FromStr};

use clap::{Parser, Subcommand};
use openssl::x509::X509;
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use stackable_telemetry::tracing::TelemetryOptions;

use crate::parsers::{pem, pkcs12};

#[derive(Parser, Debug)]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[command(flatten, next_help_heading = "Tracing options")]
    pub telemetry: TelemetryOptions,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Generate PKCS12 truststore files from PEM or PKCS12 files
    GeneratePkcs12Truststore(GeneratePkcs12TruststoreArguments),
}

#[derive(Parser, Debug)]
pub struct GeneratePkcs12TruststoreArguments {
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
    #[arg(long = "pkcs12", value_parser = Pkcs12Source::from_str)]
    pub pkcs12s: Vec<Pkcs12Source>,
}

#[derive(Debug, Snafu)]
#[snafu(display("missing path"))]
pub struct Pkcs12SourceParseError;

#[derive(Clone, Debug)]
pub struct Pkcs12Source {
    path: PathBuf,
    password: String,
}

impl FromStr for Pkcs12Source {
    type Err = Pkcs12SourceParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, ':');
        let path = parts.next().context(Pkcs12SourceParseSnafu)?;
        let password = parts.next().unwrap_or("").to_owned();

        Ok(Self {
            path: PathBuf::from(path),
            password,
        })
    }
}

impl GeneratePkcs12TruststoreArguments {
    pub fn certificate_sources(&self) -> Vec<CertInput> {
        let pems = self.pems.iter().cloned().map(CertInput::Pem);
        let pkcs12s = self.pkcs12s.iter().cloned().map(CertInput::Pkcs12);
        pems.chain(pkcs12s).collect()
    }
}

#[derive(Debug, Snafu)]
pub enum CertInputError {
    #[snafu(display("failed to read from file at {path}", path = path.display()))]
    ReadFile {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to parse file contents as PEM"))]
    ParseFileAsPem {
        source: crate::parsers::pem::ParseError,
    },

    #[snafu(display("failed to parse file contents as PKCS#12"))]
    ParseFileAsPkcs12 {
        source: crate::parsers::pkcs12::WorkaroundError,
    },

    #[snafu(display("the PEM file at {path} contained no certificates", path = path.display()))]
    NoCertificates { path: PathBuf },
}

#[derive(Debug)]
pub enum CertInput {
    Pem(PathBuf),
    Pkcs12(Pkcs12Source),
}

impl CertInput {
    pub fn from_file(&self) -> Result<Vec<X509>, CertInputError> {
        let read_file_fn = |path| fs::read(path).context(ReadFileSnafu { path });

        match self {
            CertInput::Pem(path) => {
                let file_contents = read_file_fn(path)?;

                let certs = pem::parse_contents(&file_contents).context(ParseFileAsPemSnafu)?;
                ensure!(!certs.is_empty(), NoCertificatesSnafu { path });

                Ok(certs)
            }
            CertInput::Pkcs12(Pkcs12Source { path, password }) => {
                let file_contents = read_file_fn(path)?;
                pkcs12::parse_file_workaround(&file_contents, password)
                    .context(ParseFileAsPkcs12Snafu)
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
