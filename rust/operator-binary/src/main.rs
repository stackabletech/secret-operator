use anyhow::Context;
use clap::{crate_description, crate_version, Parser};
use csi_server::{
    controller::SecretProvisionerController, identity::SecretProvisionerIdentity,
    node::SecretProvisionerNode,
};
use futures::{FutureExt, TryStreamExt};
use grpc::csi::v1::{
    controller_server::ControllerServer, identity_server::IdentityServer, node_server::NodeServer,
};
use stackable_operator::{logging::TracingTarget, CustomResourceExt};
use std::{os::unix::prelude::FileTypeExt, path::PathBuf};
use tokio::signal::unix::{signal, SignalKind};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use utils::{uds_bind_private, TonicUnixStream};

mod backend;
mod crd;
mod csi_server;
mod format;
mod grpc;
mod utils;

pub const APP_NAME: &str = "secret";

#[derive(clap::Parser)]
#[clap(author, version)]
struct Opts {
    #[clap(subcommand)]
    cmd: stackable_operator::cli::Command<SecretOperatorRun>,
}

#[derive(clap::Parser)]
struct SecretOperatorRun {
    #[clap(long, env)]
    csi_endpoint: PathBuf,
    #[clap(long, env)]
    node_name: String,
    /// Unprivileged mode disables any features that require running secret-operator in a privileged container.
    ///
    /// Currently, this means that:
    /// - Secret volumes will be stored on disk, rather than in a ramdisk
    ///
    /// Unprivileged mode is EXPERIMENTAL and heavily discouraged, since it increases the risk of leaking secrets.
    #[clap(long, env)]
    privileged: bool,
    /// Tracing log collector system
    #[arg(long, env, default_value_t, value_enum)]
    pub tracing_target: TracingTarget,
}

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        stackable_operator::cli::Command::Crd => {
            crd::SecretClass::print_yaml_schema(built_info::PKG_VERSION)?;
        }
        stackable_operator::cli::Command::Run(SecretOperatorRun {
            csi_endpoint,
            node_name,
            tracing_target,
            privileged,
        }) => {
            stackable_operator::logging::initialize_logging(
                "SECRET_PROVISIONER_LOG",
                APP_NAME,
                tracing_target,
            );
            stackable_operator::utils::print_startup_string(
                crate_description!(),
                crate_version!(),
                built_info::GIT_VERSION,
                built_info::TARGET,
                built_info::BUILT_TIME_UTC,
                built_info::RUSTC_VERSION,
            );
            let client = stackable_operator::client::create_client(Some(
                "secrets.stackable.tech".to_string(),
            ))
            .await?;
            if csi_endpoint
                .symlink_metadata()
                .map_or(false, |meta| meta.file_type().is_socket())
            {
                let _ = std::fs::remove_file(&csi_endpoint);
            }
            let mut sigterm = signal(SignalKind::terminate())?;
            Server::builder()
                .add_service(
                    tonic_reflection::server::Builder::configure()
                        .include_reflection_service(true)
                        .register_encoded_file_descriptor_set(grpc::FILE_DESCRIPTOR_SET_BYTES)
                        .build()?,
                )
                .add_service(IdentityServer::new(SecretProvisionerIdentity))
                .add_service(ControllerServer::new(SecretProvisionerController {
                    client: client.clone(),
                }))
                .add_service(NodeServer::new(SecretProvisionerNode {
                    client,
                    node_name,
                    privileged,
                }))
                .serve_with_incoming_shutdown(
                    UnixListenerStream::new(
                        uds_bind_private(csi_endpoint).context("failed to bind CSI listener")?,
                    )
                    .map_ok(TonicUnixStream),
                    sigterm.recv().map(|_| ()),
                )
                .await?;
        }
    }
    Ok(())
}
