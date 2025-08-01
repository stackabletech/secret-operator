// TODO: Look into how to properly resolve `clippy::result_large_err`.
// This will need changes in our and upstream error types.
#![allow(clippy::result_large_err)]

use std::{os::unix::prelude::FileTypeExt, path::PathBuf, pin::pin};

use anyhow::Context;
use clap::Parser;
use csi_server::{
    controller::SecretProvisionerController, identity::SecretProvisionerIdentity,
    node::SecretProvisionerNode,
};
use futures::{FutureExt, TryStreamExt};
use grpc::csi::v1::{
    controller_server::ControllerServer, identity_server::IdentityServer, node_server::NodeServer,
};
use stackable_operator::{CustomResourceExt, cli::ProductOperatorRun, telemetry::Tracing};
use tokio::signal::unix::{SignalKind, signal};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use utils::{TonicUnixStream, uds_bind_private};

mod backend;
mod crd;
mod csi_server;
mod external_crd;
mod format;
mod grpc;
mod truststore_controller;
mod utils;

pub const OPERATOR_NAME: &str = "secrets.stackable.tech";

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

    /// Unprivileged mode disables any features that require running secret-operator in a privileged container.
    ///
    /// Currently, this means that:
    /// - Secret volumes will be stored on disk, rather than in a ramdisk
    ///
    /// Unprivileged mode is EXPERIMENTAL and heavily discouraged, since it increases the risk of leaking secrets.
    #[clap(long, env)]
    privileged: bool,

    #[clap(flatten)]
    common: ProductOperatorRun,
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
            crd::TrustStore::print_yaml_schema(built_info::PKG_VERSION)?;
        }
        stackable_operator::cli::Command::Run(SecretOperatorRun {
            csi_endpoint,
            privileged,
            common:
                ProductOperatorRun {
                    product_config: _,
                    watch_namespace,
                    telemetry_arguments,
                    cluster_info_opts,
                },
        }) => {
            // NOTE (@NickLarsenNZ): Before stackable-telemetry was used:
            // - The console log level was set by `SECRET_PROVISIONER_LOG`, and is now `CONSOLE_LOG` (when using Tracing::pre_configured).
            // - The file log level was set by `SECRET_PROVISIONER_LOG`, and is now set via `FILE_LOG` (when using Tracing::pre_configured).
            // - The file log directory was set by `SECRET_PROVISIONER_LOG_DIRECTORY`, and is now set by `ROLLING_LOGS_DIR` (or via `--rolling-logs <DIRECTORY>`).
            let _tracing_guard =
                Tracing::pre_configured(built_info::PKG_NAME, telemetry_arguments).init()?;

            tracing::info!(
                built_info.pkg_version = built_info::PKG_VERSION,
                built_info.git_version = built_info::GIT_VERSION,
                built_info.target = built_info::TARGET,
                built_info.built_time_utc = built_info::BUILT_TIME_UTC,
                built_info.rustc_version = built_info::RUSTC_VERSION,
                "Starting {description}",
                description = built_info::PKG_DESCRIPTION
            );

            let client = stackable_operator::client::initialize_operator(
                Some(OPERATOR_NAME.to_string()),
                &cluster_info_opts,
            )
            .await?;
            if csi_endpoint
                .symlink_metadata()
                .is_ok_and(|meta| meta.file_type().is_socket())
            {
                let _ = std::fs::remove_file(&csi_endpoint);
            }
            let mut sigterm = signal(SignalKind::terminate())?;
            let csi_server = pin!(
                Server::builder()
                    .add_service(
                        tonic_reflection::server::Builder::configure()
                            .include_reflection_service(true)
                            .register_encoded_file_descriptor_set(grpc::FILE_DESCRIPTOR_SET_BYTES)
                            .build_v1()?,
                    )
                    .add_service(IdentityServer::new(SecretProvisionerIdentity))
                    .add_service(ControllerServer::new(SecretProvisionerController {
                        client: client.clone(),
                    }))
                    .add_service(NodeServer::new(SecretProvisionerNode {
                        client: client.clone(),
                        node_name: cluster_info_opts.kubernetes_node_name.to_owned(),
                        privileged,
                    }))
                    .serve_with_incoming_shutdown(
                        UnixListenerStream::new(
                            uds_bind_private(csi_endpoint)
                                .context("failed to bind CSI listener")?,
                        )
                        .map_ok(TonicUnixStream),
                        sigterm.recv().map(|_| ()),
                    )
            );
            let truststore_controller =
                pin!(truststore_controller::start(&client, &watch_namespace).map(Ok));
            futures::future::select(csi_server, truststore_controller)
                .await
                .factor_first()
                .0?;
        }
    }
    Ok(())
}
