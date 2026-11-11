use std::{
    fs::{File, Permissions},
    io::Write,
    os::unix::prelude::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use openssl::sha::Sha256;
use rustix::{
    fs::{CWD, FileType, Gid, Mode, OFlags, fchmod, fchown, fstat, mkdirat, openat},
    io::Errno,
};
use serde::{Deserialize, de::IntoDeserializer};
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::api::core::v1::Pod,
    kube::runtime::reflector::ObjectRef,
    kvp::{AnnotationError, Annotations},
};
use sys_mount::{Mount, MountFlags, UnmountFlags, unmount};
use tonic::{Request, Response, Status};

use super::{controller::TOPOLOGY_NODE, log_if_endpoint_error};
use crate::{
    backend::{
        self, SecretBackendError, SecretContents, SecretVolumeSelector,
        pod_info::{self, PodInfo},
    },
    format,
    grpc::csi::v1::{
        NodeExpandVolumeRequest, NodeExpandVolumeResponse, NodeGetCapabilitiesRequest,
        NodeGetCapabilitiesResponse, NodeGetInfoRequest, NodeGetInfoResponse,
        NodeGetVolumeStatsRequest, NodeGetVolumeStatsResponse, NodePublishVolumeRequest,
        NodePublishVolumeResponse, NodeServiceCapability, NodeStageVolumeRequest,
        NodeStageVolumeResponse, NodeUnpublishVolumeRequest, NodeUnpublishVolumeResponse,
        NodeUnstageVolumeRequest, NodeUnstageVolumeResponse, Topology, node_server::Node,
        node_service_capability, volume_capability,
    },
    utils::{FmtByteSlice, error_full_message},
};

#[derive(Snafu, Debug)]
#[snafu(module)]
enum PublishError {
    #[snafu(display("failed to parse selector from volume context"))]
    InvalidSelector { source: serde::de::value::Error },

    #[snafu(display("failed to get pod for volume"))]
    GetPod {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to parse pod details"))]
    ParsePod { source: pod_info::FromPodError },

    #[snafu(display("failed to initialize backend"))]
    InitBackend {
        source: backend::dynamic::FromSelectorError,
    },

    #[snafu(display("backend failed to get secret data"))]
    BackendGetSecretData { source: backend::dynamic::DynError },

    #[snafu(display("failed to create secret parent dir {path:?}"))]
    CreateDir {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to read metadata of {path:?}"))]
    ReadMetadata {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to mount volume mount directory {path:?}"))]
    Mount {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to convert secret data into desired format"))]
    FormatData { source: format::IntoFilesError },

    #[snafu(display("failed to set volume permissions for {path:?}"))]
    SetDirPermissions {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to create secret file {path:?}"))]
    CreateFile {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to write secret file {path:?}"))]
    WriteFile {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("failed to check whether provisioned marker {path:?} exists"))]
    CheckProvisionedMarker {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("provisioned marker {path:?} is not a regular file"))]
    InvalidProvisionedMarker { path: PathBuf },

    #[snafu(display("secret file {path:?} exists but is not a regular file"))]
    NotRegularFile { path: PathBuf },

    #[snafu(display("failed to set owner group and permissions of {path:?}"))]
    SetOwnership {
        source: std::io::Error,
        path: PathBuf,
    },

    #[snafu(display("volume mount group {group:?} is not a valid group ID"))]
    InvalidVolumeMountGroup { group: String },

    #[snafu(display("file path {path:?} must only contain normal components"))]
    InvalidComponents { path: PathBuf },

    #[snafu(display("file path {path:?} must not be absolute"))]
    InvalidAbsolutePath { path: PathBuf },

    #[snafu(display("failed to tag pod with expiry metadata"))]
    TagPod {
        source: stackable_operator::client::Error,
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
            PublishError::ReadMetadata { .. } => Status::unavailable(full_msg),
            PublishError::Mount { .. } => Status::unavailable(full_msg),
            PublishError::FormatData { .. } => Status::unavailable(full_msg),
            PublishError::SetDirPermissions { .. } => Status::unavailable(full_msg),
            PublishError::CreateFile { .. } => Status::unavailable(full_msg),
            PublishError::WriteFile { .. } => Status::unavailable(full_msg),
            PublishError::CheckProvisionedMarker { .. } => Status::unavailable(full_msg),
            PublishError::InvalidProvisionedMarker { .. } => Status::failed_precondition(full_msg),
            PublishError::NotRegularFile { .. } => Status::failed_precondition(full_msg),
            PublishError::SetOwnership { .. } => Status::unavailable(full_msg),
            PublishError::InvalidVolumeMountGroup { .. } => Status::invalid_argument(full_msg),
            PublishError::InvalidComponents { .. } => Status::unavailable(full_msg),
            PublishError::InvalidAbsolutePath { .. } => Status::unavailable(full_msg),
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
            // NodePublishVolume must be idempotent: the kubelet calls it again for volumes it has
            // already published, for example after a kubelet restart. Mounting on every call would
            // stack a new empty tmpfs over the previous one. The container keeps the lowest layer,
            // and `clean_secret_dir` unmounts only one layer per NodeUnpublishVolume, so removing
            // the directory fails with EBUSY until the kubelet has retried once per layer.
            // And that is the reason we check here whether a mount already exists.
            if is_mount_point(target_path).await? {
                tracing::info!(volume.path = %target_path.display(), "Volume path is already mounted, reusing the mount");
            } else {
                Mount::builder()
                    .fstype("tmpfs")
                    .flags(MountFlags::NODEV | MountFlags::NOEXEC | MountFlags::NOSUID)
                    .mount("", target_path)
                    .context(publish_error::MountSnafu { path: target_path })?;
            }
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
        selector: SecretVolumeSelector,
        group: Option<Gid>,
    ) -> Result<(), PublishError> {
        let SecretVolumeSelector {
            provision_parts,
            format,
            compat,
            names,
            ..
        } = selector;

        for (k, v) in data
            .data
            .into_files(format, names, compat, provision_parts)
            .context(publish_error::FormatDataSnafu)?
        {
            write_secret_file(target_path, Path::new(&k), &v, group)?;
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
                            .context(unpublish_error::UnmountSnafu { path: target_path });
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

/// Returns whether `path` is the root of a mount, by comparing its device with its parent's.
///
/// Bind mounts within the same filesystem are not detected.
/// That is fine for the tmpfs mounts created by [`SecretProvisionerNode::prepare_secret_dir`].
async fn is_mount_point(path: &Path) -> Result<bool, PublishError> {
    match path.parent() {
        Some(parent) => {
            let device = tokio::fs::metadata(path)
                .await
                .context(publish_error::ReadMetadataSnafu { path })?
                .dev();
            let parent_device = tokio::fs::metadata(parent)
                .await
                .context(publish_error::ReadMetadataSnafu { path: parent })?
                .dev();
            Ok(device != parent_device)
        }
        // If the path and its parent is the same, we can always return false.
        None => Ok(false),
    }
}

/// Empty file whose presence means that the secret data has been provisioned completely.
///
/// It is a dotfile so that `*` globs over the volume, as in `cp /stackable/tls/* ...`, skip it.
///
/// Processes in the Pod can write to the volume.
/// Anything other than a regular file is rejected
const PROVISIONED_MARKER_FILE_NAME: &str = ".stackable-secret-operator-data-provisioned";

async fn is_provisioned(target_path: &Path) -> Result<bool, PublishError> {
    let path = target_path.join(PROVISIONED_MARKER_FILE_NAME);
    match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => publish_error::InvalidProvisionedMarkerSnafu { path }.fail(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).context(publish_error::CheckProvisionedMarkerSnafu { path }),
    }
}

/// Must be called after all secret files are written.
async fn mark_provisioned(target_path: &Path, group: Option<Gid>) -> Result<(), PublishError> {
    write_secret_file(
        target_path,
        Path::new(PROVISIONED_MARKER_FILE_NAME),
        &[],
        group,
    )
}

/// Returns the Pod's fsGroup, which the kubelet passes because of the `VOLUME_MOUNT_GROUP` node
/// capability.
fn volume_mount_group(
    capability: Option<&crate::grpc::csi::v1::VolumeCapability>,
) -> Result<Option<Gid>, PublishError> {
    let group = capability
        .and_then(|capability| match &capability.access_type {
            Some(volume_capability::AccessType::Mount(mount)) => {
                Some(mount.volume_mount_group.as_str())
            }
            _ => None,
        })
        .filter(|group| !group.is_empty());
    group
        .map(|group| {
            group
                .parse::<u32>()
                .ok()
                // u32::MAX is -1, which leaves the group unchanged in chown(2).
                .filter(|id| *id != u32::MAX)
                .map(Gid::from_raw)
                .context(publish_error::InvalidVolumeMountGroupSnafu { group })
        })
        .transpose()
}

/// Sets `mode` on `fd`, and `group` as its group if given.
fn restrict_to_group(
    fd: impl std::os::fd::AsFd,
    mode: u32,
    group: Option<Gid>,
    path: &Path,
) -> Result<(), PublishError> {
    if let Some(group) = group {
        fchown(&fd, None, Some(group))
            .map_err(std::io::Error::from)
            .context(publish_error::SetOwnershipSnafu { path })?;
    }
    fchmod(&fd, Mode::from_raw_mode(mode))
        .map_err(std::io::Error::from)
        .context(publish_error::SetOwnershipSnafu { path })
}

/// Writes `contents` to `relative_path` beneath `root`, creating missing directories.
///
/// `relative_path` can be chosen by users, so it must be relative and only consist of normal
/// components, otherwise the write fails.
///
/// The Pod can write to the volume, so since the last publish it may have replaced any entry in
/// it, for example with a symlink. This function never follows a symlink, neither for the file
/// nor for the directories leading to it. Each directory is opened through a file descriptor of
/// the directory before it rather than by path, so replacing an entry after it has been opened
/// cannot redirect the write. It only writes into regular files: a FIFO or device node in place
/// of the file is an error.
///
/// Every directory on the way gets mode `0750` and the file `0640`, both owned by `group` if given,
/// so the Pod can read the secret but not change the volume.
fn write_secret_file(
    root: &Path,
    relative_path: &Path,
    contents: &[u8],
    group: Option<Gid>,
) -> Result<(), PublishError> {
    // Ensure that `relative_path` is indeed a relative path
    ensure!(
        !relative_path.has_root(),
        publish_error::InvalidAbsolutePathSnafu {
            path: relative_path
        }
    );

    // Ensure that all components of the path are "normal"
    // Examples for not-normal are things like "." and ".."
    ensure!(
        relative_path
            .components()
            .all(|c| matches!(c, Component::Normal(_))),
        publish_error::InvalidComponentsSnafu {
            path: relative_path
        }
    );

    // This creates the directory structure needed to get to the relative directory
    // making sure to not follow symlinks and so on
    let directory_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let file_name = relative_path
        .file_name()
        .context(publish_error::InvalidComponentsSnafu {
            path: relative_path,
        })?;

    let mut path = root.to_path_buf();
    let mut directory = openat(CWD, root, directory_flags, Mode::empty())
        .map_err(std::io::Error::from)
        .context(publish_error::CreateDirSnafu { path: &path })?;
    restrict_to_group(&directory, 0o750, group, &path)?;
    for component in relative_path
        .parent()
        .into_iter()
        .flat_map(Path::components)
    {
        let name = component.as_os_str();
        path.push(name);
        match mkdirat(&directory, name, Mode::from_raw_mode(0o777)) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(err) => {
                return Err(std::io::Error::from(err))
                    .context(publish_error::CreateDirSnafu { path });
            }
        }
        directory = openat(&directory, name, directory_flags, Mode::empty())
            .map_err(std::io::Error::from)
            .context(publish_error::CreateDirSnafu { path: &path })?;
        restrict_to_group(&directory, 0o750, group, &path)?;
    }

    // And now finally we create the actual file from `contents`
    path.push(file_name);
    let file = openat(
        &directory,
        file_name,
        OFlags::WRONLY
            | OFlags::CREATE
            // A repeated publish rewrites existing files, and regenerated keys and certificates
            // vary in length, so a shorter file would keep trailing bytes of the previous one.
            | OFlags::TRUNC
            | OFlags::NOFOLLOW
            | OFlags::NONBLOCK
            | OFlags::CLOEXEC,
        // User: root/secret-operator
        // Group: Controlled by Pod.securityContext.fsGroup, the actual application
        // (when running as unprivileged user)
        Mode::from_raw_mode(0o640),
    )
    .map_err(std::io::Error::from)
    .context(publish_error::CreateFileSnafu { path: &path })?;
    let file_type = fstat(&file)
        .map(|stat| FileType::from_raw_mode(stat.st_mode))
        .map_err(std::io::Error::from)
        .context(publish_error::CreateFileSnafu { path: &path })?;
    ensure!(
        file_type == FileType::RegularFile,
        publish_error::NotRegularFileSnafu { path }
    );
    restrict_to_group(&file, 0o640, group, &path)?;
    File::from(file)
        .write_all(contents)
        .context(publish_error::WriteFileSnafu { path })
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
                // The kubelet calls NodePublishVolume again for volumes it has already published,
                // for example after a kubelet restart. Issuing a new secret would move the expiry
                // annotation to a secret that a running process may never load, so the restarter
                // could restart the Pod only after the secret in use has expired.
                if is_provisioned(&target_path).await? {
                    tracing::info!(
                        volume.path = %target_path.display(),
                        "Volume is already published, keeping its secret data"
                    );
                    return Ok(Response::new(NodePublishVolumeResponse {}));
                }
                let group = volume_mount_group(request.volume_capability.as_ref())?;
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
                    selector,
                    group,
                )
                .await?;
                mark_provisioned(&target_path, group).await?;
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
        // With this capability the kubelet passes the Pod's fsGroup instead of making the volume
        // group-writable itself. The group only gets read access: the CSI spec recommends
        // read-write, but files the Pod can replace are files the publish path cannot trust.
        Ok(Response::new(NodeGetCapabilitiesResponse {
            capabilities: vec![NodeServiceCapability {
                r#type: Some(node_service_capability::Type::Rpc(
                    node_service_capability::Rpc {
                        r#type: node_service_capability::rpc::Type::VolumeMountGroup.into(),
                    },
                )),
            }],
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rustix::fs::{CWD, FileType, Mode, mknodat};

    use super::{
        PROVISIONED_MARKER_FILE_NAME, PublishError, is_mount_point, is_provisioned,
        mark_provisioned, write_secret_file,
    };

    #[tokio::test]
    async fn plain_directory_is_not_mount_point() {
        let dir = tempfile::tempdir().expect("temporary directory can be created");
        assert!(
            !is_mount_point(dir.path())
                .await
                .expect("metadata of temporary directory is readable")
        );
    }

    #[tokio::test]
    async fn proc_is_mount_point() {
        assert!(
            is_mount_point(Path::new("/proc"))
                .await
                .expect("metadata of /proc is readable")
        );
    }

    #[tokio::test]
    async fn empty_volume_is_not_provisioned() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        assert!(
            !is_provisioned(volume.path())
                .await
                .expect("volume directory is readable")
        );
    }

    #[tokio::test]
    async fn marked_volume_is_provisioned() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        mark_provisioned(volume.path(), None)
            .await
            .expect("provisioned marker can be written");
        assert!(
            is_provisioned(volume.path())
                .await
                .expect("volume directory is readable")
        );
    }

    #[tokio::test]
    async fn symlinked_marker_is_rejected() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        std::os::unix::fs::symlink(
            volume.path().join("missing"),
            volume.path().join(PROVISIONED_MARKER_FILE_NAME),
        )
        .expect("symlink can be created");
        assert!(is_provisioned(volume.path()).await.is_err());
    }

    #[tokio::test]
    async fn marking_does_not_follow_symlink() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        let target = volume.path().join("target");
        std::os::unix::fs::symlink(&target, volume.path().join(PROVISIONED_MARKER_FILE_NAME))
            .expect("symlink can be created");
        assert!(mark_provisioned(volume.path(), None).await.is_err());
        assert!(!target.exists());
    }

    #[test]
    fn writes_nested_secret_file() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        write_secret_file(
            volume.path(),
            Path::new("nested/tls.crt"),
            b"certificate",
            None,
        )
        .expect("secret file can be written");
        let contents =
            std::fs::read(volume.path().join("nested/tls.crt")).expect("secret file is readable");
        assert_eq!(contents, b"certificate");
    }

    #[test]
    fn rewriting_truncates_secret_file() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        write_secret_file(volume.path(), Path::new("tls.key"), b"longer key", None)
            .expect("secret file can be written");
        write_secret_file(volume.path(), Path::new("tls.key"), b"key", None)
            .expect("secret file can be rewritten");
        let contents =
            std::fs::read(volume.path().join("tls.key")).expect("secret file is readable");
        assert_eq!(contents, b"key");
    }

    #[test]
    fn symlinked_secret_file_is_not_followed() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        let outside = tempfile::tempdir().expect("temporary directory can be created");
        let target = outside.path().join("victim");
        std::fs::write(&target, "untouched").expect("symlink target can be written");
        std::os::unix::fs::symlink(&target, volume.path().join("tls.crt"))
            .expect("symlink can be created");

        assert!(
            write_secret_file(volume.path(), Path::new("tls.crt"), b"certificate", None).is_err()
        );
        let contents = std::fs::read_to_string(&target).expect("symlink target is readable");
        assert_eq!(contents, "untouched");
    }

    #[test]
    fn symlinked_directory_is_not_followed() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        let outside = tempfile::tempdir().expect("temporary directory can be created");
        std::os::unix::fs::symlink(outside.path(), volume.path().join("nested"))
            .expect("symlink can be created");

        assert!(
            write_secret_file(
                volume.path(),
                Path::new("nested/tls.crt"),
                b"certificate",
                None
            )
            .is_err()
        );
        assert!(!outside.path().join("tls.crt").exists());
    }

    #[test]
    fn fifo_in_place_of_secret_file_is_rejected() {
        let volume = tempfile::tempdir().expect("temporary directory can be created");
        mknodat(
            CWD,
            volume.path().join("tls.crt"),
            FileType::Fifo,
            Mode::from_raw_mode(0o600),
            0,
        )
        .expect("FIFO can be created");

        let result = write_secret_file(volume.path(), Path::new("tls.crt"), b"certificate", None);
        assert!(matches!(
            result,
            Err(PublishError::NotRegularFile { .. } | PublishError::CreateFile { .. })
        ));
    }

    #[test]
    fn secret_file_outside_volume_is_rejected() {
        let root = tempfile::tempdir().expect("temporary directory can be created");
        let volume = root.path().join("volume");
        std::fs::create_dir(&volume).expect("volume directory can be created");

        for path in ["../escaped", "/escaped", "nested/../../escaped"] {
            assert!(write_secret_file(&volume, Path::new(path), b"certificate", None).is_err());
        }
        assert!(!root.path().join("escaped").exists());
    }

    #[test]
    fn secret_file_is_readable_but_not_writable_by_group() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let volume = tempfile::tempdir().expect("temporary directory can be created");
        let group = rustix::fs::Gid::from_raw(
            std::fs::metadata(volume.path())
                .expect("metadata is readable")
                .gid(),
        );
        let file = volume.path().join("nested/tls.crt");
        write_secret_file(
            volume.path(),
            Path::new("nested/tls.crt"),
            b"certificate",
            None,
        )
        .expect("secret file can be written");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o660))
            .expect("permissions can be widened");

        write_secret_file(
            volume.path(),
            Path::new("nested/tls.crt"),
            b"certificate",
            Some(group),
        )
        .expect("secret file can be rewritten");

        for (path, mode) in [
            (volume.path().to_path_buf(), 0o750),
            (volume.path().join("nested"), 0o750),
            (file, 0o640),
        ] {
            let metadata = std::fs::metadata(&path).expect("metadata is readable");
            assert_eq!(metadata.mode() & 0o777, mode, "mode of {path:?}");
            assert_eq!(metadata.gid(), group.as_raw(), "group of {path:?}");
        }
    }
}
