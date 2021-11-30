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
    Deserialize,
};
use stackable_operator::{k8s_openapi::api::core::v1::Secret, kube};
use std::{collections::HashMap, os::unix::prelude::FileTypeExt, path::PathBuf};
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
        let ctx = SecretVolumeContext::deserialize(ctx_deserializer).unwrap();
        let data = match ctx.source {
            SecretSource::Secret {
                secret_name,
                namespace,
            } => {
                let secrets = kube::Api::<Secret>::namespaced(self.kube.clone(), &namespace);
                let secret = secrets.get(&secret_name).await.unwrap();
                secret.data.unwrap_or_default()
            }
        };
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
struct SecretVolumeContext {
    #[serde(flatten)]
    source: SecretSource,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", tag = "secrets.stackable.tech/type")]
enum SecretSource {
    Secret {
        #[serde(rename = "secrets.stackable.tech/secret.name")]
        secret_name: String,
        #[serde(rename = "csi.storage.k8s.io/pod.namespace")]
        namespace: String,
    },
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
