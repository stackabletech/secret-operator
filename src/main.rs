use futures::TryStreamExt;
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
use pin_project::pin_project;
use serde::{
    de::{value::MapDeserializer, IntoDeserializer},
    Deserialize, Deserializer,
};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::{Pod, Secret},
        apimachinery::pkg::apis::meta::v1::LabelSelector,
        ByteString,
    },
    kube::{self, api::ListParams},
};
use std::{
    collections::{BTreeMap, HashMap},
    os::unix::prelude::FileTypeExt,
    path::PathBuf,
};
use structopt::StructOpt;
use tokio::{
    fs::{create_dir_all, File},
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{
    transport::{server::Connected, Server},
    Request, Response, Status,
};

mod grpc;

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

struct SecretProvisionerNode {
    kube: kube::Client,
}

impl SecretProvisionerNode {
    async fn get_secret_data(&self, sel: SecretVolumeSelector) -> BTreeMap<String, ByteString> {
        let pods = kube::Api::<Pod>::namespaced(self.kube.clone(), &sel.namespace);
        let secrets = kube::Api::<Secret>::namespaced(self.kube.clone(), &sel.namespace);
        let pod = pods.get(&sel.pod).await.unwrap();
        let mut label_selector = BTreeMap::new();
        label_selector.insert("secrets.stackable.tech/type".to_string(), sel.ty);
        for scope in sel.scope {
            match scope {
                SecretScope::Node => {
                    label_selector.insert(
                        "secrets.stackable.tech/node".to_string(),
                        pod.spec.as_ref().unwrap().node_name.clone().unwrap(),
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
            .unwrap();
        secrets
            .list(&ListParams::default().labels(&label_selector))
            .await
            .unwrap()
            .items
            .remove(0)
            .data
            .unwrap_or_default()
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
        dbg!(&request);
        let request = request.into_inner();
        let target_path = PathBuf::from(request.target_path);
        let ctx_deserializer: MapDeserializer<_, serde::de::value::Error> =
            request.volume_context.into_deserializer();
        let sel = SecretVolumeSelector::deserialize(ctx_deserializer).unwrap();
        let data = self.get_secret_data(sel).await;
        for (k, v) in data {
            let item_path = target_path.join(k);
            if let Some(item_path_parent) = item_path.parent() {
                create_dir_all(item_path_parent).await.unwrap();
            }
            File::create(item_path)
                .await
                .unwrap()
                .write_all(&v.0)
                .await
                .unwrap();
        }
        Ok(Response::new(NodePublishVolumeResponse {}))
    }

    async fn node_unpublish_volume(
        &self,
        request: Request<NodeUnpublishVolumeRequest>,
    ) -> Result<Response<NodeUnpublishVolumeResponse>, tonic::Status> {
        dbg!(&request);
        let request = request.into_inner();
        let target_path = PathBuf::from(request.target_path);
        tokio::fs::remove_dir_all(target_path).await.unwrap();
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
    Server::builder()
        .add_service(
            tonic_reflection::server::Builder::configure()
                .include_reflection_service(true)
                .register_encoded_file_descriptor_set(grpc::FILE_DESCRIPTOR_SET_BYTES)
                .build()?,
        )
        .add_service(IdentityServer::new(SecretProvisionerIdentity))
        .add_service(NodeServer::new(SecretProvisionerNode { kube }))
        .serve_with_incoming(
            UnixListenerStream::new(UnixListener::bind(opts.csi_endpoint)?).map_ok(TonicUnixStream),
        )
        .await?;
    Ok(())
}

#[pin_project]
struct TonicUnixStream(#[pin] UnixStream);

impl AsyncRead for TonicUnixStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().0.poll_read(cx, buf)
    }
}

impl AsyncWrite for TonicUnixStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().0.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().0.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

impl Connected for TonicUnixStream {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}
