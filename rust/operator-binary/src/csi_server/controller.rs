use std::collections::BTreeMap;

use serde::{Deserialize, de::IntoDeserializer};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod},
    kube::runtime::reflector::ObjectRef,
};
use tonic::{Code, Request, Response, Status};
use uuid::Uuid;

use super::log_if_endpoint_error;
use crate::{
    backend::{
        self, InternalSecretVolumeSelectorParams, SecretBackendError, SecretVolumeSelector,
        pod_info::{self, SchedulingPodInfo},
    },
    grpc::csi::{
        self,
        v1::{
            ControllerGetCapabilitiesResponse, ControllerServiceCapability, CreateVolumeResponse,
            DeleteVolumeResponse, Topology, Volume, controller_server::Controller,
            controller_service_capability,
        },
    },
    utils::error_full_message,
};

pub const TOPOLOGY_NODE: &str = "secrets.stackable.tech/node";

#[derive(Snafu, Debug)]
#[snafu(module)]
enum CreateVolumeError {
    #[snafu(display("failed to parse CreateVolume parameters"))]
    InvalidParams { source: serde::de::value::Error },

    #[snafu(display("failed to load {pvc}"))]
    FindPvc {
        source: stackable_operator::client::Error,
        pvc: ObjectRef<PersistentVolumeClaim>,
    },

    #[snafu(display("failed to resolve owning Pod of {pvc}"))]
    ResolveOwnerPod {
        pvc: ObjectRef<PersistentVolumeClaim>,
    },

    #[snafu(display("failed to get pod for volume"))]
    GetPod {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to parse pod details"))]
    ParsePod { source: pod_info::FromPodError },

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

/// Rewrites the gRPC codes that `external-provisioner` treats as "the operation may still be
/// running, call CreateVolume again later" into a terminal code.
///
/// Such a code makes the provisioner park the PVC in an in-memory map that is only ever cleared
/// on success or on a terminal code. Its PVC delete handler is a no-op, so a PVC that is deleted
/// while parked is instead resurrected from the provisioner's stale copy and retried forever, on
/// every node, since the provisioner runs in a DaemonSet without leader election.
///
/// [`Controller::create_volume`] never leaves anything running in the background - it creates no
/// state per volume, which is also why [`Controller::delete_volume`] has nothing to do - so none
/// of these codes may escape it. The backends still use them for [`Controller::node_publish_volume`],
/// where they are correct, and so must be rewritten here rather than at their source.
///
/// See <https://github.com/stackabletech/secret-operator/issues/722>.
fn make_terminal(code: Code) -> Code {
    match code {
        Code::Unavailable | Code::Aborted | Code::Cancelled | Code::DeadlineExceeded => {
            Code::Internal
        }
        code => code,
    }
}

impl From<CreateVolumeError> for Status {
    fn from(err: CreateVolumeError) -> Self {
        let full_msg = error_full_message(&err);
        // Convert to an appropriate tonic::Status representation and include full error message
        let raw_code = match err {
            CreateVolumeError::InvalidParams { .. } => Code::InvalidArgument,
            CreateVolumeError::FindPvc { .. } => Code::FailedPrecondition,
            CreateVolumeError::ResolveOwnerPod { .. } => Code::FailedPrecondition,
            CreateVolumeError::GetPod { .. } => Code::FailedPrecondition,
            CreateVolumeError::ParsePod { .. } => Code::FailedPrecondition,
            CreateVolumeError::InvalidSecretSelector { .. } => Code::FailedPrecondition,
            CreateVolumeError::InitBackend { source } => source.grpc_code(),
            CreateVolumeError::FindNodes { source } => source.grpc_code(),
            // CSI defines ResourceExhausted as "unable to provision in accessible_topology", which
            // describes this case, but external-provisioner turns it into ProvisioningReschedule
            // whenever the volume has a selected node, so it strips the node annotation and the
            // scheduler picks another one. No node ever satisfies the scopes here, so the retry is
            // futile.
            // Additionally that path is not rate limited: the claim is forgotten rather than
            // requeued, leaving the scheduler to re-trigger it immediately.
            //
            // It only stays dormant today because the operator has no `update` on
            // persistentvolumeclaims and the annotation delete therefore fails (see roles.yaml).
            // FailedPrecondition does not depend on that.
            CreateVolumeError::NoMatchingNode => Code::FailedPrecondition,
        };

        // Applied to every variant, including the codes inherited from the backends (which are
        // only known at runtime), so that no future variant can reintroduce the retry loop.
        let code = make_terminal(raw_code);
        if code != raw_code {
            tracing::debug!(
                grpc.code.original = ?raw_code,
                grpc.code.returned = ?code,
                "rewrote CreateVolume error code:"
            );
        }

        Status::new(code, full_msg)
    }
}

pub struct SecretProvisionerController {
    pub client: stackable_operator::client::Client,
}

impl SecretProvisionerController {
    async fn get_pvc_secret_selector(
        &self,
        params: &CreateVolumeParams,
    ) -> Result<(BTreeMap<String, String>, SecretVolumeSelector), CreateVolumeError> {
        // PersistentVolumeClaim doesn't allow users to set arbitrary custom storage parameters,
        // so instead we load the PVC and treat _its_ annotations as parameters
        let pvc = self
            .client
            .get::<PersistentVolumeClaim>(&params.pvc_name, &params.pvc_namespace)
            .await
            .with_context(|_| create_volume_error::FindPvcSnafu {
                pvc: ObjectRef::new(&params.pvc_name).within(&params.pvc_namespace),
            })?;
        let mut pvc_selector = pvc.metadata.annotations.unwrap_or_default();

        // Inject internal selector params
        let internal_selector_params = InternalSecretVolumeSelectorParams {
            pvc_name: Some(params.pvc_name.clone()),
        };
        pvc_selector.extend(
            // Convert to BTreeMap while letting serde ensure that all
            // field names and serializations are correct
            serde_json::to_value(internal_selector_params)
                .and_then(serde_json::from_value::<BTreeMap<String, String>>)
                .expect("internal selector params failed to reserialize"),
        );

        // Kubernetes doesn't inform CSI controllers about the Pod
        // associated with each volume (since, /normally/, volume creation
        // is supposed to be independent from any Pod mounting it).
        // Thus, we try to discover it ourselves instead, and add that.
        // We specifically avoid adding it to the volume context, since it /will/
        // be provided by the Kubelet during publish/mount.
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
        let mut raw_selector = pvc_selector.clone();
        raw_selector.extend([
            ("csi.storage.k8s.io/pod.name".to_string(), pod_name),
            (
                "csi.storage.k8s.io/pod.namespace".to_string(),
                params.pvc_namespace.clone(),
            ),
        ]);
        Ok((
            pvc_selector,
            SecretVolumeSelector::deserialize(raw_selector.into_deserializer()).with_context(
                |_| create_volume_error::InvalidSecretSelectorSnafu {
                    pvc: ObjectRef::new(&params.pvc_name).within(&params.pvc_namespace),
                },
            )?,
        ))
    }
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
        use create_volume_error::*;
        log_if_endpoint_error(
            "failed to create volume",
            async move {
                let request = request.into_inner();
                let params =
                    CreateVolumeParams::deserialize(request.parameters.into_deserializer())
                        .context(InvalidParamsSnafu)?;
                let (pvc_selector, selector) = self.get_pvc_secret_selector(&params).await?;

                let pod = self
                    .client
                    .get::<Pod>(&selector.pod, &selector.namespace)
                    .await
                    .context(GetPodSnafu)?;
                let pod_info = SchedulingPodInfo::from_pod(&self.client, &pod, &selector.scope)
                    .await
                    .context(ParsePodSnafu)?;

                let backend = backend::dynamic::from_selector(&self.client, &selector)
                    .await
                    .context(create_volume_error::InitBackendSnafu)?;
                let accessible_topology = match backend
                    .get_qualified_node_names(&selector, pod_info)
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
                        // We don't care about the volume ID ourselves, but generate something unique
                        // in case anyone else relies on it for some kind of deduplication
                        volume_id: Uuid::new_v4().to_string(),
                        accessible_topology,
                        volume_context: pvc_selector.into_iter().collect(),
                        ..Volume::default()
                    }),
                }))
            }
            .await,
        )
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

    async fn controller_modify_volume(
        &self,
        _request: Request<csi::v1::ControllerModifyVolumeRequest>,
    ) -> Result<Response<csi::v1::ControllerModifyVolumeResponse>, Status> {
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

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::make_terminal;

    /// Every code `external-provisioner` reads as "may still be running in the background".
    const RETRIED_FOREVER: [Code; 4] = [
        Code::Unavailable,
        Code::Aborted,
        Code::Cancelled,
        Code::DeadlineExceeded,
    ];

    /// Every variant of [`CreateVolumeError`] funnels through [`make_terminal`], including the
    /// codes inherited from the backends, so covering the whole code space here covers every
    /// error `CreateVolume` can produce.
    #[test]
    fn create_volume_never_returns_a_retried_forever_code() {
        for raw in 0..=16 {
            let code = Code::from_i32(raw);
            assert!(
                !RETRIED_FOREVER.contains(&make_terminal(code)),
                "{code:?} must not be returned by CreateVolume, it makes external-provisioner \
                 retry the PVC forever (issue #722)"
            );
        }
    }

    /// The rewrite must only touch the codes that cause the retry loop.
    #[test]
    fn make_terminal_leaves_other_codes_alone() {
        for raw in 0..=16 {
            let code = Code::from_i32(raw);
            if !RETRIED_FOREVER.contains(&code) {
                assert_eq!(make_terminal(code), code);
            }
        }
    }
}
