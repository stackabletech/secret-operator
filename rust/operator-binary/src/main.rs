// TODO: Look into how to properly resolve `clippy::result_large_err`.
// This will need changes in our and upstream error types.
#![allow(clippy::result_large_err)]

use std::{os::unix::prelude::FileTypeExt, path::PathBuf};

use anyhow::{Context, anyhow};
use clap::Parser;
use csi_server::{
    controller::SecretProvisionerController, identity::SecretProvisionerIdentity,
    node::SecretProvisionerNode,
};
use futures::{FutureExt, TryFutureExt, TryStreamExt, try_join};
use grpc::csi::v1::{
    controller_server::ControllerServer, identity_server::IdentityServer, node_server::NodeServer,
};
use stackable_operator::{
    YamlSchema,
    cli::{CommonOptions, RunArguments},
    client::Client,
    kvp::{Label, LabelExt},
    shared::yaml::SerializeOptions,
    telemetry::Tracing,
    webhook::servers::ConversionWebhookServer,
};
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::oneshot,
};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use utils::{TonicUnixStream, uds_bind_private};

use crate::crd::{SecretClass, SecretClassVersion, TrustStore, TrustStoreVersion, v1alpha2};

mod backend;
mod crd;
mod csi_server;
mod external_crd;
mod format;
mod grpc;
mod truststore_controller;
mod utils;

pub const OPERATOR_NAME: &str = "secrets.stackable.tech";
pub const FIELD_MANAGER: &str = "secret-operator";

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
    common: RunArguments,
}

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();
    match opts.cmd {
        stackable_operator::cli::Command::Crd => {
            SecretClass::merged_crd(crd::SecretClassVersion::V1Alpha2)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
            TrustStore::merged_crd(crd::TrustStoreVersion::V1Alpha1)?
                .print_yaml_schema(built_info::PKG_VERSION, SerializeOptions::default())?;
        }
        stackable_operator::cli::Command::Run(SecretOperatorRun {
            csi_endpoint,
            privileged,
            common:
                RunArguments {
                    common:
                        CommonOptions {
                            telemetry,
                            cluster_info,
                        },
                    product_config: _,
                    watch_namespace,
                    operator_environment,
                    maintenance,
                },
        }) => {
            // NOTE (@NickLarsenNZ): Before stackable-telemetry was used:
            // - The console log level was set by `SECRET_PROVISIONER_LOG`, and is now `CONSOLE_LOG` (when using Tracing::pre_configured).
            // - The file log level was set by `SECRET_PROVISIONER_LOG`, and is now set via `FILE_LOG` (when using Tracing::pre_configured).
            // - The file log directory was set by `SECRET_PROVISIONER_LOG_DIRECTORY`, and is now set by `ROLLING_LOGS_DIR` (or via `--rolling-logs <DIRECTORY>`).
            let _tracing_guard = Tracing::pre_configured(built_info::PKG_NAME, telemetry).init()?;

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
                &cluster_info,
            )
            .await?;

            if csi_endpoint
                .symlink_metadata()
                .is_ok_and(|meta| meta.file_type().is_socket())
            {
                let _ = std::fs::remove_file(&csi_endpoint);
            }

            // NOTE (@Techassi): This could maybe be moved into a setup function again. For now,
            // it is here.
            let crds_and_handlers = [
                (
                    SecretClass::merged_crd(SecretClassVersion::V1Alpha2)?,
                    SecretClass::try_convert as fn(_) -> _,
                ),
                (
                    TrustStore::merged_crd(TrustStoreVersion::V1Alpha1)?,
                    TrustStore::try_convert as fn(_) -> _,
                ),
            ];

            let (conversion_webhook, crd_maintainer, initial_reconcile_rx) =
                ConversionWebhookServer::with_maintainer(
                    crds_and_handlers,
                    &operator_environment.operator_service_name,
                    &operator_environment.operator_namespace,
                    FIELD_MANAGER,
                    maintenance.disable_crd_maintenance,
                    client.as_kube_client(),
                )
                .await
                .context("failed to create conversion webhook server and CRD maintainer")?;

            let mut sigterm = signal(SignalKind::terminate())?;
            let csi_server = Server::builder()
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
                    node_name: cluster_info.kubernetes_node_name.to_owned(),
                    privileged,
                }))
                .serve_with_incoming_shutdown(
                    UnixListenerStream::new(
                        uds_bind_private(csi_endpoint).context("failed to bind CSI listener")?,
                    )
                    .map_ok(TonicUnixStream),
                    sigterm.recv().map(|_| ()),
                )
                .map_err(|err| anyhow!(err).context("failed to run csi server"));

            let truststore_controller =
                truststore_controller::start(&client, &watch_namespace).map(anyhow::Ok);

            let conversion_webhook = conversion_webhook
                .run()
                .map_err(|err| anyhow!(err).context("failed to run conversion webhook"));

            let crd_maintainer = crd_maintainer
                .run()
                .map_err(|err| anyhow!(err).context("failed to run CRD maintainer"));

            let default_secretclass = create_default_secretclass(
                initial_reconcile_rx,
                operator_environment.operator_namespace.clone(),
                client.clone(),
            )
            .map_err(|err| anyhow!(err).context("failed to apply default custom resources"));

            try_join!(
                csi_server,
                truststore_controller,
                conversion_webhook,
                crd_maintainer,
                default_secretclass,
            )?;
        }
    }
    Ok(())
}

async fn create_default_secretclass(
    initial_reconcile_rx: oneshot::Receiver<()>,
    operator_namespace: String,
    client: Client,
) -> anyhow::Result<()> {
    initial_reconcile_rx.await?;

    tracing::info!("applying default secretclass");

    let deserializer = serde_yaml::Deserializer::from_slice(include_bytes!("secretclass.yaml"));
    let mut tls_secret_class: v1alpha2::SecretClass =
        serde_yaml::with::singleton_map_recursive::deserialize(deserializer)
            .expect("compile-time included secretclass must be valid YAML");

    #[rustfmt::skip]
    let managed_by = Label::managed_by(OPERATOR_NAME, "secretclass").expect("managed-by label must be valid");
    let version = Label::version(built_info::PKG_VERSION).expect("version label must be valid");
    let instance = Label::instance(OPERATOR_NAME).expect("instance label must be valid");
    let name = Label::name(OPERATOR_NAME).expect("name label must be valid");

    tls_secret_class
        .add_label(managed_by)
        .add_label(version)
        .add_label(instance)
        .add_label(name)
        .add_label(Label::stackable_vendor());

    tls_secret_class.metadata.namespace = Some(operator_namespace);

    client.create_if_missing(&tls_secret_class).await?;

    Ok(())
}
