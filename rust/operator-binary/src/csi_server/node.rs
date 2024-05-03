use std::{
    fs::Permissions,
    os::unix::prelude::PermissionsExt,
    path::{Path, PathBuf},
};

use openssl::sha::Sha256;
use serde::{de::IntoDeserializer, Deserialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    builder::ObjectMetaBuilder,
    k8s_openapi::api::core::v1::Pod,
    kube::runtime::reflector::ObjectRef,
    kvp::{AnnotationError, Annotations},
};
use sys_mount::{unmount, Mount, MountFlags, UnmountFlags};
use tokio::{
    fs::{create_dir_all, OpenOptions},
    io::AsyncWriteExt,
};
use tonic::{Request, Response, Status};

use crate::{
    backend::{
        self, pod_info, pod_info::PodInfo, SecretBackendError, SecretContents, SecretVolumeSelector,
    },
    format::{self, well_known::CompatibilityOptions, SecretFormat},
    grpc::csi::v1::{
        node_server::Node, NodeExpandVolumeRequest, NodeExpandVolumeResponse,
        NodeGetCapabilitiesRequest, NodeGetCapabilitiesResponse, NodeGetInfoRequest,
        NodeGetInfoResponse, NodeGetVolumeStatsRequest, NodeGetVolumeStatsResponse,
        NodePublishVolumeRequest, NodePublishVolumeResponse, NodeStageVolumeRequest,
        NodeStageVolumeResponse, NodeUnpublishVolumeRequest, NodeUnpublishVolumeResponse,
        NodeUnstageVolumeRequest, NodeUnstageVolumeResponse, Topology,
    },
    utils::{error_full_message, FmtByteSlice},
};

use super::controller::TOPOLOGY_NODE;

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

    #[snafu(display("failed to initialize backend"))]
    InitBackend {
        source: backend::dynamic::FromSelectorError,
    },

    #[snafu(display("backend failed to get secret data"))]
    BackendGetSecretData { source: backend::dynamic::DynError },

    #[snafu(display("failed to create secret parent dir {}", path.display()))]
    CreateDir {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to mount volume mount directory {}", path.display()))]
    Mount {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to convert secret data into desired format"))]
    FormatData { source: format::IntoFilesError },

    #[snafu(display("failed to set volume permissions for {}", path.display()))]
    SetDirPermissions {
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

    #[snafu(display("failed to tag pod with expiry metadata"))]
    TagPod {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("failed to build annotation"))]
    BuildAnnotation { source: AnnotationError },
}

// Useful since all service calls return a [Result<tonic::Response<T>, tonic::Status>]
impl From<PublishError> for Status {
    fn from(err: PublishError) -> Self {
        let full_msg = error_full_message(&err);
        // Convert to an appropriate tonic::Status representation and include full error message
        match err {
            PublishError::InvalidSelector { .. } => Status::invalid_argument(full_msg),
            PublishError::GetPod { .. } => Status::failed_precondition(full_msg),
            PublishError::ParsePod { .. } => Status::failed_precondition(full_msg),
            PublishError::InitBackend { source } => Status::new(source.grpc_code(), full_msg),
            PublishError::BackendGetSecretData { source } => {
                Status::new(source.grpc_code(), full_msg)
            }
            PublishError::CreateDir { .. } => Status::unavailable(full_msg),
            PublishError::Mount { .. } => Status::unavailable(full_msg),
            PublishError::FormatData { .. } => Status::unavailable(full_msg),
            PublishError::SetDirPermissions { .. } => Status::unavailable(full_msg),
            PublishError::CreateFile { .. } => Status::unavailable(full_msg),
            PublishError::WriteFile { .. } => Status::unavailable(full_msg),
            PublishError::TagPod { .. } => Status::unavailable(full_msg),
            PublishError::BuildAnnotation { .. } => Status::unavailable(full_msg),
        }
    }
}

#[derive(Snafu, Debug)]
#[snafu(module)]
enum UnpublishError {
    #[snafu(display("failed to unmount volume mount directory {}", path.display()))]
    Unmount {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to delete volume mount directory {}", path.display()))]
    Delete {
        source: std::io::Error,
        path: PathBuf,
    },
}

// Useful since all service calls return a [Result<tonic::Response<T>, tonic::Status>]
impl From<UnpublishError> for Status {
    fn from(err: UnpublishError) -> Self {
        let full_msg = error_full_message(&err);
        // Convert to an appropriate tonic::Status representation and include full error message
        match err {
            UnpublishError::Unmount { .. } => Status::unavailable(full_msg),
            UnpublishError::Delete { .. } => Status::unavailable(full_msg),
        }
    }
}

// The actual provisioner that is run on all nodes and in charge of provisioning and storing
// secrets for pods that get scheduled on that node.
pub struct SecretProvisionerNode {
    pub client: stackable_operator::client::Client,
    pub node_name: String,
    pub privileged: bool,
}

impl SecretProvisionerNode {
    async fn get_pod_info(&self, selector: &SecretVolumeSelector) -> Result<PodInfo, PublishError> {
        let pod = self
            .client
            .get::<Pod>(&selector.pod, &selector.namespace)
            .await
            .context(publish_error::GetPodSnafu)?;
        PodInfo::from_pod(&self.client, pod, &selector.scope)
            .await
            .context(publish_error::ParsePodSnafu)
    }

    async fn prepare_secret_dir(&self, target_path: &Path) -> Result<(), PublishError> {
        match tokio::fs::create_dir(target_path).await {
            Ok(_) => {}
            Err(err) => match err.kind() {
                std::io::ErrorKind::AlreadyExists => {
                    tracing::warn!(volume.path = %target_path.display(), "Tried to create volume path that already exists");
                }
                _ => return Err(err).context(publish_error::CreateDirSnafu { path: target_path }),
            },
        }
        if self.privileged {
            Mount::builder()
                .fstype("tmpfs")
                .flags(MountFlags::NODEV | MountFlags::NOEXEC | MountFlags::NOSUID)
                .mount("", target_path)
                .context(publish_error::MountSnafu { path: target_path })?;
        } else {
            tracing::info!("Running in unprivileged mode, not creating mount for secret volume");
        }
        // User: root/secret-operator
        // Group: Controlled by Pod.securityContext.fsGroup, the actual application
        // (when running as unprivileged user)
        tokio::fs::set_permissions(target_path, Permissions::from_mode(0o750))
            .await
            .context(publish_error::SetDirPermissionsSnafu { path: target_path })?;
        Ok(())
    }

    // Takes a path and list of filenames and content.
    // Writes all files to the target directory.
    async fn save_secret_data(
        &self,
        target_path: &Path,
        data: SecretContents,
        format: Option<SecretFormat>,
        compat: &CompatibilityOptions,
    ) -> Result<(), PublishError> {
        let create_secret = {
            let mut opts = OpenOptions::new();
            opts.create(true)
                .write(true)
                // User: root/secret-operator
                // Group: Controlled by Pod.securityContext.fsGroup, the actual application
                // (when running as unprivileged user)
                .mode(0o640);
            opts
        };
        for (k, v) in data
            .data
            .into_files(format, compat)
            .context(publish_error::FormatDataSnafu)?
        {
            let item_path = target_path.join(k);
            if let Some(item_path_parent) = item_path.parent() {
                create_dir_all(item_path_parent)
                    .await
                    .context(publish_error::CreateDirSnafu {
                        path: item_path_parent,
                    })?;
            }
            create_secret
                .open(&item_path)
                .await
                .context(publish_error::CreateFileSnafu { path: &item_path })?
                .write_all(&v)
                .await
                .context(publish_error::WriteFileSnafu { path: item_path })?;
        }
        Ok(())
    }

    async fn tag_pod(
        &self,
        client: &stackable_operator::client::Client,
        volume_id: &str,
        selector: &SecretVolumeSelector,
        data: &SecretContents,
    ) -> Result<(), PublishError> {
        // Each volume must have a unique tag, so that multiple markers of the same type can coexist on the same pod
        // Each tag needs to be simple and unique-ish per volume
        let mut volume_tag_hasher = Sha256::new();
        volume_tag_hasher.update("secrets.stackable.tech/volume:".as_bytes());
        volume_tag_hasher.update(volume_id.as_bytes());
        let volume_tag = volume_tag_hasher.finish();
        // Truncating sha256 hashes opens up some collision vulnerabilities
        // (https://csrc.nist.gov/CSRC/media/Events/First-Cryptographic-Hash-Workshop/documents/Kelsey_Truncation.pdf)
        // however, we mostly just care about preventing accidental hashes here, for which plain byte truncation should be "good enough".
        let volume_tag = &volume_tag[..16];

        let mut annotations = Annotations::new();

        if let Some(expires_after) = data.expires_after {
            annotations
                .parse_insert((
                    format!(
                        "restarter.stackable.tech/expires-at.{:x}",
                        FmtByteSlice(volume_tag)
                    ),
                    expires_after.to_rfc3339(),
                ))
                .context(publish_error::BuildAnnotationSnafu)?;
        }

        if !annotations.is_empty() {
            let tagged_pod = Pod {
                metadata: ObjectMetaBuilder::new()
                    .name(&selector.pod)
                    .namespace(&selector.namespace)
                    .annotations(annotations)
                    .build(),
                ..Pod::default()
            };
            client
                .merge_patch(&tagged_pod, &tagged_pod)
                .await
                .context(publish_error::TagPodSnafu)?;
        }
        Ok(())
    }

    async fn clean_secret_dir(&self, target_path: &Path) -> Result<(), UnpublishError> {
        // unmount() fails unconditionally with PermissionDenied when running in an unprivileged container,
        // even if it wouldn't be sensible to even try anyway (such as when there is no volume mount).
        if self.privileged {
            match unmount(target_path, UnmountFlags::empty()) {
                Ok(_) => {}
                Err(err) => match err.kind() {
                    std::io::ErrorKind::NotFound => {
                        tracing::warn!(volume.path = %target_path.display(), "Tried to unmount volume path that does not exist, assuming it was already deleted");
                        return Ok(());
                    }
                    std::io::ErrorKind::InvalidInput => {
                        tracing::warn!(volume.path = %target_path.display(), "Tried to unmount volume path that is not mounted, trying to delete it anyway");
                    }
                    _ => {
                        return Err(err)
                            .context(unpublish_error::UnmountSnafu { path: target_path })
                    }
                },
            };
        }
        // There is no mount in unprivileged mode, so we need to remove all contents in that case.
        // This may still apply to privileged mode, in case users are migrating from unprivileged to privileged mode.
        match tokio::fs::remove_dir_all(&target_path).await {
            Ok(_) => Ok(()),
            // We already catch this above when running in privileged mode, but in unprivileged mode this is still possible
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(volume.path = %target_path.display(), "Tried to delete volume path that does not exist, assuming it was already deleted");
                Ok(())
            }
            Err(err) => Err(err).context(unpublish_error::DeleteSnafu { path: target_path }),
        }
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
    ) -> Result<Response<NodeStageVolumeResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn node_unstage_volume(
        &self,
        _request: Request<NodeUnstageVolumeRequest>,
    ) -> Result<Response<NodeUnstageVolumeResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    // Called when a volume is bound to a pod on this node.
    // Creates and stores the certificates.
    async fn node_publish_volume(
        &self,
        request: Request<NodePublishVolumeRequest>,
    ) -> Result<Response<NodePublishVolumeResponse>, Status> {
        log_if_endpoint_error(
            "failed to publish volume",
            async move {
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
                let backend = backend::dynamic::from_selector(&self.client, &selector)
                    .await
                    .context(publish_error::InitBackendSnafu)?;
                let pod_ref = ObjectRef::<Pod>::new(&selector.pod).within(&selector.namespace);
                tracing::info!(pod = %pod_ref, ?selector, ?pod_info, ?backend, "issuing secret for Pod");
                let data = backend
                    .get_secret_data(&selector, pod_info)
                    .await
                    .context(publish_error::BackendGetSecretDataSnafu)?;
                self.tag_pod(&self.client, &request.volume_id, &selector, &data)
                    .await?;
                self.prepare_secret_dir(&target_path).await?;
                self.save_secret_data(
                    &target_path,
                    data,
                    selector.format,
                    &CompatibilityOptions {
                        tls_pkcs12_password: selector.compat_tls_pkcs12_password,
                    },
                )
                .await?;
                Ok(Response::new(NodePublishVolumeResponse {}))
            }
            .await,
        )
    }

    // Called when a pod is terminated that contained a volume created by this provider.
    // Deletes the target directory which the publish step ran in.
    // This means that any other files that were placed into that directory (for example by
    // init containers will also be deleted during this step.
    async fn node_unpublish_volume(
        &self,
        request: Request<NodeUnpublishVolumeRequest>,
    ) -> Result<Response<NodeUnpublishVolumeResponse>, Status> {
        log_if_endpoint_error(
            "Failed to unpublish volume",
            async move {
                let request = request.into_inner();
                let target_path = PathBuf::from(request.target_path);
                tracing::info!(
                    volume.path = %target_path.display(),
                    "Received NodeUnpublishVolume request"
                );
                self.clean_secret_dir(&target_path).await?;
                Ok(Response::new(NodeUnpublishVolumeResponse {}))
            }
            .await,
        )
    }

    async fn node_get_volume_stats(
        &self,
        _request: Request<NodeGetVolumeStatsRequest>,
    ) -> Result<Response<NodeGetVolumeStatsResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn node_expand_volume(
        &self,
        _request: Request<NodeExpandVolumeRequest>,
    ) -> Result<Response<NodeExpandVolumeResponse>, Status> {
        Err(Status::unimplemented("endpoint not implemented"))
    }

    async fn node_get_capabilities(
        &self,
        _request: Request<NodeGetCapabilitiesRequest>,
    ) -> Result<Response<NodeGetCapabilitiesResponse>, Status> {
        Ok(Response::new(NodeGetCapabilitiesResponse {
            capabilities: vec![],
        }))
    }

    async fn node_get_info(
        &self,
        _request: Request<NodeGetInfoRequest>,
    ) -> Result<Response<NodeGetInfoResponse>, Status> {
        Ok(Response::new(NodeGetInfoResponse {
            node_id: self.node_name.clone(),
            max_volumes_per_node: i64::MAX,
            accessible_topology: Some(Topology {
                segments: [(TOPOLOGY_NODE.to_string(), self.node_name.clone())].into(),
            }),
        }))
    }
}

fn log_if_endpoint_error<T, E: std::error::Error + 'static>(
    error_msg: &str,
    res: Result<T, E>,
) -> Result<T, E> {
    if let Err(err) = &res {
        tracing::warn!(error = err as &dyn std::error::Error, "{error_msg}");
    }
    res
}
