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
use serde::{de::IntoDeserializer, Deserialize, Deserializer};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::{Pod, Secret},
        apimachinery::pkg::apis::meta::v1::LabelSelector,
        ByteString,
    },
    kube::{self, api::ListParams, runtime::reflector::ObjectRef},
};
use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    os::unix::prelude::FileTypeExt,
    path::{Path, PathBuf},
};
use structopt::StructOpt;
use tokio::{
    fs::{create_dir_all, File},
    io::AsyncWriteExt,
    net::UnixListener,
    signal::unix::{signal, SignalKind},
};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{transport::Server, Request, Response, Status};
use utils::TonicUnixStream;

mod grpc;
mod utils;

struct SecretProvisionerIdentity;

#[tonic::async_trait]
impl Identity for SecretProvisionerIdentity {
    async fn get_plugin_info(
        &self,
        _request: Request<GetPluginInfoRequest>,
    ) -> Result<Response<GetPluginInfoResponse>, Status> {
        Ok(Response::new(GetPluginInfoResponse {
            name: "secrets.stackable.tech".to_string(),
            vendor_version: "0.0.0".to_string(),
            manifest: HashMap::new(),
        }))
    }

    async fn get_plugin_capabilities(
        &self,
        _request: Request<GetPluginCapabilitiesRequest>,
    ) -> Result<Response<GetPluginCapabilitiesResponse>, Status> {
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

#[derive(thiserror::Error, Debug)]
enum PublishError {
    #[error("failed to parse selector from volume context")]
    InvalidSelector(#[source] serde::de::value::Error),
    #[error("failed to find {1} owning the volume")]
    OwnerPodNotFound(#[source] kube::Error, ObjectRef<Pod>),
    #[error("owner {0} has no associated node")]
    OwnerPodHasNoNode(ObjectRef<Pod>),
    #[error("failed to build secret selector")]
    SecretSelector(#[source] stackable_operator::error::Error),
    #[error("failed to query for secrets")]
    SecretQuery(#[source] kube::Error),
    #[error("no secrets matched query {0}")]
    NoSecret(String),
    #[error("failed to create secret parent dir {1}")]
    CreateDir(#[source] std::io::Error, PathBuf),
    #[error("failed to create secret file {1}")]
    CreateFile(#[source] std::io::Error, PathBuf),
    #[error("failed to write secret file {1}")]
    WriteFile(#[source] std::io::Error, PathBuf),
}

impl From<PublishError> for tonic::Status {
    fn from(err: PublishError) -> Self {
        let mut full_msg = format!("{}", err);
        let mut curr_err = err.source();
        while let Some(curr_source) = curr_err {
            full_msg.push_str(&format!(": {}", err));
            curr_err = curr_source.source();
        }
        match err {
            PublishError::InvalidSelector(_) => tonic::Status::invalid_argument(full_msg),
            PublishError::OwnerPodNotFound(_, _) => tonic::Status::failed_precondition(full_msg),
            PublishError::OwnerPodHasNoNode(_) => tonic::Status::failed_precondition(full_msg),
            PublishError::SecretSelector(_) => tonic::Status::failed_precondition(full_msg),
            PublishError::SecretQuery(_) => tonic::Status::failed_precondition(full_msg),
            PublishError::NoSecret(_) => tonic::Status::failed_precondition(full_msg),
            PublishError::CreateDir(_, _) => tonic::Status::unavailable(full_msg),
            PublishError::CreateFile(_, _) => tonic::Status::unavailable(full_msg),
            PublishError::WriteFile(_, _) => tonic::Status::unavailable(full_msg),
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum UnpublishError {
    #[error("failed to clean up volume mount directory {1}")]
    Cleanup(#[source] std::io::Error, PathBuf),
}

impl From<UnpublishError> for tonic::Status {
    fn from(err: UnpublishError) -> Self {
        let mut full_msg = format!("{}", err);
        let mut curr_err = err.source();
        while let Some(curr_source) = curr_err {
            full_msg.push_str(&format!(": {}", err));
            curr_err = curr_source.source();
        }
        match err {
            UnpublishError::Cleanup(_, _) => tonic::Status::unavailable(full_msg),
        }
    }
}

struct SecretProvisionerNode {
    kube: kube::Client,
}

impl SecretProvisionerNode {
    async fn get_secret_data(
        &self,
        sel: SecretVolumeSelector,
    ) -> Result<BTreeMap<String, ByteString>, PublishError> {
        let pods = kube::Api::<Pod>::namespaced(self.kube.clone(), &sel.namespace);
        let secrets = kube::Api::<Secret>::namespaced(self.kube.clone(), &sel.namespace);
        let pod_ref = ObjectRef::new(&sel.pod).within(&sel.namespace);
        let pod = pods
            .get(&sel.pod)
            .await
            .map_err(|err| PublishError::OwnerPodNotFound(err, pod_ref.clone()))?;
        let mut label_selector = BTreeMap::new();
        label_selector.insert("secrets.stackable.tech/type".to_string(), sel.ty);
        for scope in sel.scope {
            match scope {
                SecretScope::Node => {
                    label_selector.insert(
                        "secrets.stackable.tech/node".to_string(),
                        pod.spec
                            .as_ref()
                            .and_then(|pod_spec| pod_spec.node_name.clone())
                            .ok_or_else(|| PublishError::OwnerPodHasNoNode(pod_ref.clone()))?,
                    );
                }
                SecretScope::Pod => {
                    label_selector
                        .insert("secrets.stackable.tech/pod".to_string(), sel.pod.clone());
                }
            }
        }
        let label_selector =
            stackable_operator::label_selector::convert_label_selector_to_query_string(
                &LabelSelector {
                    match_expressions: None,
                    match_labels: Some(label_selector),
                },
            )
            .map_err(PublishError::SecretSelector)?;
        Ok(secrets
            .list(&ListParams::default().labels(&label_selector))
            .await
            .map_err(PublishError::SecretQuery)?
            .items
            .into_iter()
            .next()
            .ok_or(PublishError::NoSecret(label_selector))?
            .data
            .unwrap_or_default())
    }

    async fn save_secret_data(
        &self,
        target_path: &Path,
        data: BTreeMap<String, ByteString>,
    ) -> Result<(), PublishError> {
        for (k, v) in data {
            let item_path = target_path.join(k);
            if let Some(item_path_parent) = item_path.parent() {
                create_dir_all(item_path_parent)
                    .await
                    .map_err(|err| PublishError::CreateDir(err, item_path_parent.into()))?;
            }
            File::create(item_path)
                .await
                .map_err(|err| PublishError::CreateFile(err, target_path.into()))?
                .write_all(&v.0)
                .await
                .map_err(|err| PublishError::WriteFile(err, target_path.into()))?;
        }
        Ok(())
    }
}

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

    async fn node_publish_volume(
        &self,
        request: Request<NodePublishVolumeRequest>,
    ) -> Result<Response<NodePublishVolumeResponse>, tonic::Status> {
        let request = request.into_inner();
        let target_path = PathBuf::from(request.target_path);
        tracing::info!(
            volume.path = %target_path.display(),
            volume.ctx = ?request.volume_context,
            "Received NodePublishVolume request"
        );
        let sel = SecretVolumeSelector::deserialize(request.volume_context.into_deserializer())
            .map_err(PublishError::InvalidSelector)?;
        let data = self.get_secret_data(sel).await?;
        self.save_secret_data(&target_path, data).await?;
        Ok(Response::new(NodePublishVolumeResponse {}))
    }

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
            .map_err(|err| UnpublishError::Cleanup(err, target_path))?;
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

#[derive(Deserialize)]
struct SecretVolumeSelector {
    #[serde(rename = "secrets.stackable.tech/type")]
    ty: String,
    #[serde(
        rename = "secrets.stackable.tech/scope",
        default,
        deserialize_with = "SecretScope::deserialize_vec"
    )]
    scope: Vec<SecretScope>,
    #[serde(rename = "csi.storage.k8s.io/pod.name")]
    pod: String,
    #[serde(rename = "csi.storage.k8s.io/pod.namespace")]
    namespace: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum SecretScope {
    Node,
    Pod,
}

impl SecretScope {
    fn deserialize_vec<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<Self>, D::Error> {
        let scopes_str = String::deserialize(de)?;
        let scopes_split = scopes_str.split(',').collect::<Vec<_>>();
        Vec::<Self>::deserialize(scopes_split.into_deserializer())
    }
}

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, env)]
    csi_endpoint: PathBuf,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    stackable_operator::logging::initialize_logging("SECRET_PROVISIONER_LOG");
    let opts = Opts::from_args();
    let kube = kube::Client::try_default().await?;
    if opts
        .csi_endpoint
        .symlink_metadata()
        .map_or(false, |meta| meta.file_type().is_socket())
    {
        let _ = std::fs::remove_file(&opts.csi_endpoint);
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
        .add_service(NodeServer::new(SecretProvisionerNode { kube }))
        .serve_with_incoming_shutdown(
            UnixListenerStream::new(UnixListener::bind(opts.csi_endpoint)?).map_ok(TonicUnixStream),
            sigterm.recv().map(|_| ()),
        )
        .await?;
    Ok(())
}
