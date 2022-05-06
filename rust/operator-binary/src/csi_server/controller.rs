use crate::{
    backend::{self, SecretBackendError, SecretVolumeSelector},
    grpc::csi::{
        self,
        v1::{
            controller_server::Controller, controller_service_capability,
            ControllerGetCapabilitiesResponse, ControllerServiceCapability, CreateVolumeResponse,
            DeleteVolumeResponse, Topology, Volume,
        },
    },
    utils::error_full_message,
};
use serde::{de::IntoDeserializer, Deserialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::api::core::v1::PersistentVolumeClaim, kube::runtime::reflector::ObjectRef,
};
use tonic::{Request, Response, Status};

pub const TOPOLOGY_NODE: &str = "secrets.stackable.tech/node";

#[derive(Snafu, Debug)]
#[snafu(module)]
enum CreateVolumeError {
    #[snafu(display("failed to parse CreateVolume parameters"))]
    InvalidParams { source: serde::de::value::Error },
    #[snafu(display("failed to load {pvc}"))]
    FindPvc {
        source: stackable_operator::error::Error,
        pvc: ObjectRef<PersistentVolumeClaim>,
    },
    #[snafu(display("failed to resolve owning Pod of {pvc}"))]
    ResolveOwnerPod {
        pvc: ObjectRef<PersistentVolumeClaim>,
    },
    #[snafu(display("failed to parse secret selector from annotations of {pvc}"))]
    InvalidSecretSelector {
        source: serde::de::value::Error,
        pvc: ObjectRef<PersistentVolumeClaim>,
    },
    #[snafu(display("failed to initialize backend"))]
    InitBackend {
        source: backend::dynamic::FromSelectorError,
    },
    #[snafu(display("failed to find nodes matching scopes"))]
    FindNodes { source: backend::dynamic::DynError },
    #[snafu(display("no nodes match scopes"))]
    NoMatchingNode,
}

impl From<CreateVolumeError> for Status {
    fn from(err: CreateVolumeError) -> Self {
        let full_msg = error_full_message(&err);
        // Convert to an appropriate tonic::Status representation and include full error message
        match err {
            CreateVolumeError::InvalidParams { .. } => Status::invalid_argument(full_msg),
            CreateVolumeError::FindPvc { .. } => Status::unavailable(full_msg),
            CreateVolumeError::ResolveOwnerPod { .. } => Status::failed_precondition(full_msg),
            CreateVolumeError::InvalidSecretSelector { .. } => {
                Status::failed_precondition(full_msg)
            }
            CreateVolumeError::InitBackend { source } => Status::new(source.grpc_code(), full_msg),
            CreateVolumeError::FindNodes { source } => Status::new(source.grpc_code(), full_msg),
            CreateVolumeError::NoMatchingNode => Status::unavailable(full_msg),
        }
    }
}

pub struct SecretProvisionerController {
    pub client: stackable_operator::client::Client,
}

#[tonic::async_trait]
impl Controller for SecretProvisionerController {
    async fn controller_get_capabilities(
        &self,
        _request: Request<csi::v1::ControllerGetCapabilitiesRequest>,
    ) -> Result<Response<csi::v1::ControllerGetCapabilitiesResponse>, Status> {
        Ok(Response::new(ControllerGetCapabilitiesResponse {
            capabilities: vec![ControllerServiceCapability {
                r#type: Some(controller_service_capability::Type::Rpc(
                    controller_service_capability::Rpc {
                        r#type: controller_service_capability::rpc::Type::CreateDeleteVolume.into(),
                    },
                )),
            }],
        }))
    }

    async fn create_volume(
        &self,
        request: Request<csi::v1::CreateVolumeRequest>,
    ) -> Result<Response<csi::v1::CreateVolumeResponse>, Status> {
        let request = request.into_inner();
        let params = CreateVolumeParams::deserialize(request.parameters.into_deserializer())
            .context(create_volume_error::InvalidParamsSnafu)?;
        let pvc = self
            .client
            .get::<PersistentVolumeClaim>(&params.pvc_name, Some(&params.pvc_namespace))
            .await
            .with_context(|_| create_volume_error::FindPvcSnafu {
                pvc: ObjectRef::new(&params.pvc_name).within(&params.pvc_namespace),
            })?;
        let pod_name = pvc
            .metadata
            .owner_references
            .unwrap_or_default()
            .into_iter()
            .find(|owner| {
                owner.controller.unwrap_or(false)
                    && owner.kind == "Pod"
                    // Only respect Pods from the k8s core api group
                    && !owner.api_version.contains('/')
            })
            .with_context(|| create_volume_error::ResolveOwnerPodSnafu {
                pvc: ObjectRef::new(&params.pvc_name).within(&params.pvc_namespace),
            })?
            .name;
        let pvc_selector = pvc.metadata.annotations.unwrap_or_default();
        let mut raw_selector = pvc_selector.clone();
        raw_selector.extend([
            ("csi.storage.k8s.io/pod.name".to_string(), pod_name),
            (
                "csi.storage.k8s.io/pod.namespace".to_string(),
                params.pvc_namespace.clone(),
            ),
        ]);
        let selector = SecretVolumeSelector::deserialize(raw_selector.into_deserializer())
            .with_context(|_| create_volume_error::InvalidSecretSelectorSnafu {
                pvc: ObjectRef::new(&params.pvc_name).within(&params.pvc_namespace),
            })?;
        let backend = backend::dynamic::from_selector(&self.client, &selector)
            .await
            .context(create_volume_error::InitBackendSnafu)?;
        let accessible_topology = match backend
            .get_qualified_node_names(&selector)
            .await
            .context(create_volume_error::FindNodesSnafu)?
        {
            // No node constraints apply to this volume, so allow any topology
            None => Vec::new(),
            // No nodes match the constraints on this volume, so fail
            Some(nodes) if nodes.is_empty() => {
                return Err(create_volume_error::NoMatchingNodeSnafu.build().into());
            }
            // Matching nodes were found, only allow scheduling to them
            Some(nodes) => nodes
                .into_iter()
                .map(|node| Topology {
                    segments: [(TOPOLOGY_NODE.to_string(), node)].into(),
                })
                .collect(),
        };
        Ok(Response::new(CreateVolumeResponse {
            volume: Some(Volume {
                volume_id: "asdf".to_string(),
                accessible_topology,
                volume_context: pvc_selector.into_iter().collect(),
                ..Volume::default()
            }),
        }))
    }

    async fn delete_volume(
        &self,
        _request: Request<csi::v1::DeleteVolumeRequest>,
    ) -> Result<Response<csi::v1::DeleteVolumeResponse>, Status> {
        // Nothing to delete since we maintain no global state per PV
        Ok(Response::new(DeleteVolumeResponse {}))
    }

    async fn controller_publish_volume(
        &self,
        _request: Request<csi::v1::ControllerPublishVolumeRequest>,
    ) -> Result<Response<csi::v1::ControllerPublishVolumeResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn controller_unpublish_volume(
        &self,
        _request: Request<csi::v1::ControllerUnpublishVolumeRequest>,
    ) -> Result<Response<csi::v1::ControllerUnpublishVolumeResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn validate_volume_capabilities(
        &self,
        _request: Request<csi::v1::ValidateVolumeCapabilitiesRequest>,
    ) -> Result<Response<csi::v1::ValidateVolumeCapabilitiesResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn list_volumes(
        &self,
        _request: Request<csi::v1::ListVolumesRequest>,
    ) -> Result<Response<csi::v1::ListVolumesResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn get_capacity(
        &self,
        _request: Request<csi::v1::GetCapacityRequest>,
    ) -> Result<Response<csi::v1::GetCapacityResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn create_snapshot(
        &self,
        _request: Request<csi::v1::CreateSnapshotRequest>,
    ) -> Result<Response<csi::v1::CreateSnapshotResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn delete_snapshot(
        &self,
        _request: Request<csi::v1::DeleteSnapshotRequest>,
    ) -> Result<Response<csi::v1::DeleteSnapshotResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn list_snapshots(
        &self,
        _request: Request<csi::v1::ListSnapshotsRequest>,
    ) -> Result<Response<csi::v1::ListSnapshotsResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn controller_expand_volume(
        &self,
        _request: Request<csi::v1::ControllerExpandVolumeRequest>,
    ) -> Result<Response<csi::v1::ControllerExpandVolumeResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn controller_get_volume(
        &self,
        _request: Request<csi::v1::ControllerGetVolumeRequest>,
    ) -> Result<Response<csi::v1::ControllerGetVolumeResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }
}

#[derive(Deserialize)]
struct CreateVolumeParams {
    #[serde(rename = "csi.storage.k8s.io/pvc/name")]
    pvc_name: String,
    #[serde(rename = "csi.storage.k8s.io/pvc/namespace")]
    pvc_namespace: String,
}
