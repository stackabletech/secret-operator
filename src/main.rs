use backend::{pod_info, SecretBackendError};
use clap::{crate_description, crate_version, StructOpt};
use crd::SecretClass;
use futures::{FutureExt, TryStreamExt};
use grpc::csi::v1::{
    identity_server::{Identity, IdentityServer},
    node_server::{Node, NodeServer},
    GetPluginCapabilitiesRequest, GetPluginCapabilitiesResponse, GetPluginInfoRequest,
    GetPluginInfoResponse, NodeExpandVolumeRequest, NodeExpandVolumeResponse,
    NodeGetCapabilitiesRequest, NodeGetCapabilitiesResponse, NodeGetInfoRequest,
    NodeGetInfoResponse, NodeGetVolumeStatsRequest, NodeGetVolumeStatsResponse,
    NodePublishVolumeRequest, NodePublishVolumeResponse, NodeStageVolumeRequest,
    NodeStageVolumeResponse, NodeUnpublishVolumeRequest, NodeUnpublishVolumeResponse,
    NodeUnstageVolumeRequest, NodeUnstageVolumeResponse, ProbeRequest, ProbeResponse,
};
use serde::{de::IntoDeserializer, Deserialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::api::core::v1::Pod,
    kube::{runtime::reflector::ObjectRef, CustomResourceExt},
};
use std::{
    collections::HashMap,
    error::Error,
    os::unix::prelude::FileTypeExt,
    path::{Path, PathBuf},
};
use tokio::{
    fs::{create_dir_all, File},
    io::AsyncWriteExt,
    signal::unix::{signal, SignalKind},
};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};
use utils::{uds_bind_private, TonicUnixStream};

use crate::backend::{pod_info::PodInfo, SecretVolumeSelector};

mod backend;
mod crd;
mod grpc;
mod utils;

struct SecretProvisionerIdentity;

// The identity services are mandatory to implement, we deliver some minimal responses here
// https://github.com/container-storage-interface/spec/blob/master/spec.md#rpc-interface
#[tonic::async_trait]
impl Identity for SecretProvisionerIdentity {
    async fn get_plugin_info(
        &self,
        _request: Request<GetPluginInfoRequest>,
    ) -> Result<Response<GetPluginInfoResponse>, Status> {
        Ok(Response::new(GetPluginInfoResponse {
            name: "secrets.stackable.tech".to_string(),
            vendor_version: crate_version!().to_string(),
            manifest: HashMap::new(),
        }))
    }

    async fn get_plugin_capabilities(
        &self,
        _request: Request<GetPluginCapabilitiesRequest>,
    ) -> Result<Response<GetPluginCapabilitiesResponse>, Status> {
        // It is ok to return an empty vec here, as a minimal set of capabilities is
        // is mandatory to implement. This list only refers to optional capabilities.
        Ok(Response::new(GetPluginCapabilitiesResponse {
            capabilities: Vec::new(),
        }))
    }

    async fn probe(
        &self,
        _request: Request<ProbeRequest>,
    ) -> Result<Response<ProbeResponse>, Status> {
        Ok(Response::new(ProbeResponse { ready: Some(true) }))
    }
}

#[derive(Snafu, Debug)]
#[snafu(module)]
enum PublishError {
    #[snafu(display("failed to parse selector from volume context"))]
    InvalidSelector { source: serde::de::value::Error },
    #[snafu(display("failed to get pod for volume"))]
    GetPod {
        source: stackable_operator::error::Error,
    },
    #[snafu(display("failed to parse pod details"))]
    ParsePod { source: pod_info::FromPodError },
    #[snafu(display("failed to get {class}"))]
    GetClass {
        source: stackable_operator::error::Error,
        class: ObjectRef<SecretClass>,
    },
    #[snafu(display("failed to initialize backend for {class}"))]
    GetBackend {
        source: backend::dynamic::FromClassError,
        class: ObjectRef<SecretClass>,
    },
    #[snafu(display("backend failed to get secret data"))]
    BackendGetSecretData { source: backend::dynamic::DynError },
    #[snafu(display("failed to create secret parent dir {}", path.display()))]
    CreateDir {
        source: std::io::Error,
        path: PathBuf,
    },
    #[snafu(display("failed to create secret file {}", path.display()))]
    CreateFile {
        source: std::io::Error,
        path: PathBuf,
    },
    #[snafu(display("failed to write secret file {}", path.display()))]
    WriteFile {
        source: std::io::Error,
        path: PathBuf,
    },
}

// Useful since all service calls return a [Result<tonic::Response<T>, tonic::Status>]
impl From<PublishError> for tonic::Status {
    fn from(err: PublishError) -> Self {
        // Build the full hierarchy of error messages by walking up the stack until an error
        // without `source` set is encountered and concatenating all encountered error strings.
        let mut full_msg = format!("{}", err);
        let mut curr_err = err.source();
        while let Some(curr_source) = curr_err {
            full_msg.push_str(&format!(": {}", curr_source));
            curr_err = curr_source.source();
        }
        // Convert to an appropriate tonic::Status representation and include full error message
        match err {
            PublishError::InvalidSelector { .. } => tonic::Status::invalid_argument(full_msg),
            PublishError::GetPod { .. } => tonic::Status::failed_precondition(full_msg),
            PublishError::ParsePod { .. } => tonic::Status::failed_precondition(full_msg),
            PublishError::GetClass { .. } => tonic::Status::failed_precondition(full_msg),
            PublishError::GetBackend { source, .. } => {
                tonic::Status::new(source.grpc_code(), full_msg)
            }
            PublishError::BackendGetSecretData { source } => {
                tonic::Status::new(source.grpc_code(), full_msg)
            }
            PublishError::CreateDir { .. } => tonic::Status::unavailable(full_msg),
            PublishError::CreateFile { .. } => tonic::Status::unavailable(full_msg),
            PublishError::WriteFile { .. } => tonic::Status::unavailable(full_msg),
        }
    }
}

#[derive(Snafu, Debug)]
#[snafu(module)]
enum UnpublishError {
    #[snafu(display("failed to clean up volume mount directory {}", path.display()))]
    Cleanup {
        source: std::io::Error,
        path: PathBuf,
    },
}

// Useful since all service calls return a [Result<tonic::Response<T>, tonic::Status>]
impl From<UnpublishError> for tonic::Status {
    fn from(err: UnpublishError) -> Self {
        // Build the full hierarchy of error messages by walking up the stack until an error
        // without `source` set is encountered and concatenating all encountered error strings.
        let mut full_msg = format!("{}", err);
        let mut curr_err = err.source();
        while let Some(curr_source) = curr_err {
            full_msg.push_str(&format!(": {}", err));
            curr_err = curr_source.source();
        }
        // Convert to an appropriate tonic::Status representation and include full error message
        match err {
            UnpublishError::Cleanup { .. } => tonic::Status::unavailable(full_msg),
        }
    }
}

// The actual provisioner that is run on all nodes and in charge of provisioning and storing
// secrets for pods that get scheduled on that node.
struct SecretProvisionerNode {
    client: stackable_operator::client::Client,
}

impl SecretProvisionerNode {
    async fn get_pod_info(&self, selector: &SecretVolumeSelector) -> Result<PodInfo, PublishError> {
        let pod = self
            .client
            .get::<Pod>(&selector.pod, Some(&selector.namespace))
            .await
            .context(publish_error::GetPodSnafu)?;
        PodInfo::from_pod(&self.client, pod)
            .await
            .context(publish_error::ParsePodSnafu)
    }

    async fn get_secret_backend(
        &self,
        selector: &SecretVolumeSelector,
    ) -> Result<Box<backend::Dynamic>, PublishError> {
        let class_ref = || ObjectRef::new(&selector.class);
        let class = self
            .client
            .get::<SecretClass>(&selector.class, None)
            .await
            .with_context(|_| publish_error::GetClassSnafu { class: class_ref() })?;
        backend::dynamic::from_class(&self.client, class)
            .await
            .with_context(|_| publish_error::GetBackendSnafu { class: class_ref() })
    }

    // Takes a path and list of filenames and content.
    // Writes all files to the target directory.
    async fn save_secret_data(
        &self,
        target_path: &Path,
        data: HashMap<PathBuf, Vec<u8>>,
    ) -> Result<(), PublishError> {
        for (k, v) in data {
            let item_path = target_path.join(k);
            if let Some(item_path_parent) = item_path.parent() {
                create_dir_all(item_path_parent)
                    .await
                    .context(publish_error::CreateDirSnafu {
                        path: item_path_parent,
                    })?;
            }
            File::create(item_path)
                .await
                .context(publish_error::CreateFileSnafu { path: target_path })?
                .write_all(&v)
                .await
                .context(publish_error::WriteFileSnafu { path: target_path })?;
        }
        Ok(())
    }
}

// Most of the services are not yet implemented, most of them will never be, because they are
// not needed for this use case.
// The main two services are publish_volume und unpublish_volume, which get called whenever a
// volume is bound to a pod on this node.
#[tonic::async_trait]
impl Node for SecretProvisionerNode {
    async fn node_stage_volume(
        &self,
        _request: Request<NodeStageVolumeRequest>,
    ) -> Result<Response<NodeStageVolumeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("endpoint not implemented"))
    }

    async fn node_unstage_volume(
        &self,
        _request: Request<NodeUnstageVolumeRequest>,
    ) -> Result<Response<NodeUnstageVolumeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("endpoint not implemented"))
    }

    // Called when a volume is bound to a pod on this node.
    // Creates and stores the certificates.
    async fn node_publish_volume(
        &self,
        request: Request<NodePublishVolumeRequest>,
    ) -> Result<Response<NodePublishVolumeResponse>, tonic::Status> {
        let request = request.into_inner();
        let target_path = PathBuf::from(request.target_path);
        tracing::info!(
            volume.path = %target_path.display(),
            "Received NodePublishVolume request"
        );
        let selector =
            SecretVolumeSelector::deserialize(request.volume_context.into_deserializer())
                .context(publish_error::InvalidSelectorSnafu)?;
        let pod_info = self.get_pod_info(&selector).await?;
        let backend = self.get_secret_backend(&selector).await?;
        let data = backend
            .get_secret_data(selector, pod_info)
            .await
            .context(publish_error::BackendGetSecretDataSnafu)?;
        self.save_secret_data(&target_path, data).await?;
        Ok(Response::new(NodePublishVolumeResponse {}))
    }

    // Called when a pod is terminated that contained a volume created by this provider.
    // Deletes the target directory which the publish step ran in.
    // This means that any other files that were placed into that directory (for example by
    // init containers will also be deleted during this step.
    async fn node_unpublish_volume(
        &self,
        request: Request<NodeUnpublishVolumeRequest>,
    ) -> Result<Response<NodeUnpublishVolumeResponse>, tonic::Status> {
        let request = request.into_inner();
        let target_path = PathBuf::from(request.target_path);
        tracing::info!(
            volume.path = %target_path.display(),
            "Received NodeUnpublishVolume request"
        );
        tokio::fs::remove_dir_all(&target_path)
            .await
            .context(unpublish_error::CleanupSnafu { path: target_path })?;
        Ok(Response::new(NodeUnpublishVolumeResponse {}))
    }

    async fn node_get_volume_stats(
        &self,
        _request: Request<NodeGetVolumeStatsRequest>,
    ) -> Result<Response<NodeGetVolumeStatsResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("endpoint not implemented"))
    }

    async fn node_expand_volume(
        &self,
        _request: Request<NodeExpandVolumeRequest>,
    ) -> Result<Response<NodeExpandVolumeResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("endpoint not implemented"))
    }

    async fn node_get_capabilities(
        &self,
        _request: Request<NodeGetCapabilitiesRequest>,
    ) -> Result<Response<NodeGetCapabilitiesResponse>, tonic::Status> {
        Ok(Response::new(NodeGetCapabilitiesResponse {
            capabilities: vec![],
        }))
    }

    async fn node_get_info(
        &self,
        _request: Request<NodeGetInfoRequest>,
    ) -> Result<Response<NodeGetInfoResponse>, tonic::Status> {
        Ok(Response::new(NodeGetInfoResponse {
            node_id: "asdf".to_string(),
            max_volumes_per_node: i64::MAX,
            accessible_topology: None,
        }))
    }
}

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
}

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
    pub const TARGET: Option<&str> = option_env!("TARGET");
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    stackable_operator::logging::initialize_logging("SECRET_PROVISIONER_LOG");
    let opts = Opts::parse();
    match opts.cmd {
        stackable_operator::cli::Command::Crd => {
            println!("{}", serde_yaml::to_string(&crd::SecretClass::crd())?)
        }
        stackable_operator::cli::Command::Run(SecretOperatorRun { csi_endpoint }) => {
            stackable_operator::utils::print_startup_string(
                crate_description!(),
                crate_version!(),
                built_info::GIT_VERSION,
                built_info::TARGET.unwrap_or("unknown target"),
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
                .add_service(NodeServer::new(SecretProvisionerNode { client }))
                .serve_with_incoming_shutdown(
                    UnixListenerStream::new(uds_bind_private(csi_endpoint)?)
                        .map_ok(TonicUnixStream),
                    sigterm.recv().map(|_| ()),
                )
                .await?;
        }
    }
    Ok(())
}
