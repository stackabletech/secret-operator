use clap::Parser;
use snafu::{ResultExt, Snafu};
use stackable_telemetry::Tracing;

use crate::cli::{Cli, Command};

mod cert_ext;
mod cli;
mod cmds;
mod parsers;

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("failed to initialize tracing"))]
    InitializeTracing {
        source: stackable_telemetry::tracing::Error,
    },

    #[snafu(display("failed to generate PKCS12 truststore"))]
    GeneratePkcs12Truststore { source: cmds::pkcs12::Error },
}

#[snafu::report]
pub fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // Use `CONSOLE_LOG_LEVEL` to modify the console log level
    let _tracing_guard = Tracing::pre_configured(built_info::PKG_NAME, cli.telemetry)
        .init()
        .context(InitializeTracingSnafu)?;

    match cli.command {
        Command::GeneratePkcs12Truststore(args) => {
            cmds::pkcs12::generate_truststore(args).context(GeneratePkcs12TruststoreSnafu)
        }
    }
}
