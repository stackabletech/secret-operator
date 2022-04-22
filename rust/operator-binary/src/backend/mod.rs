//! Collects or generates secret data based on the request in the Kubernetes `Volume` definition

pub mod dynamic;
pub mod k8s_search;
pub mod pod_info;
pub mod scope;
pub mod tls;

use async_trait::async_trait;
use serde::Deserialize;
use stackable_operator::k8s_openapi::chrono::{DateTime, FixedOffset};
use std::{collections::HashMap, convert::Infallible, path::PathBuf};

pub use dynamic::Dynamic;
pub use k8s_search::K8sSearch;
pub use tls::TlsGenerate;

use pod_info::Address;
use scope::SecretScope;

/// Configuration provided by the `Volume` selecting what secret data should be provided
///
/// Fields beginning with `csi.storage.k8s.io/` are provided by the Kubelet
#[derive(Deserialize)]
pub struct SecretVolumeSelector {
    /// What kind of secret should be used
    #[serde(rename = "secrets.stackable.tech/class")]
    pub class: String,
    /// Scopes define what the secret identifies about a pod
    ///
    /// Currently supported scopes:
    /// - `pod` - The name and address of the pod itself
    /// - `node` - The Kubernetes `Node` that the pod is running on
    /// - `service` - A Kubernetes `Service` that the pod is participating in, this takes the name of the service in the format `service=foo`
    ///
    /// Multiple scopes are supported, these should be provided in a comma-separated list (for example: `pod,node`)
    #[serde(
        rename = "secrets.stackable.tech/scope",
        default,
        deserialize_with = "SecretScope::deserialize_vec"
    )]
    pub scope: Vec<scope::SecretScope>,
    /// The name of the `Pod`, provided by Kubelet
    #[serde(rename = "csi.storage.k8s.io/pod.name")]
    pub pod: String,
    /// The name of the `Pod`'s `Namespace`, provided by Kubelet
    #[serde(rename = "csi.storage.k8s.io/pod.namespace")]
    pub namespace: String,
}

impl SecretVolumeSelector {
    /// Returns all addresses associated with a certain [`SecretScope`]
    fn scope_addresses<'a>(
        &'a self,
        pod_info: &'a pod_info::PodInfo,
        scope: &scope::SecretScope,
    ) -> Vec<Address> {
        match scope {
            scope::SecretScope::Node => {
                let mut addrs = vec![Address::Dns(pod_info.node_name.clone())];
                addrs.extend(pod_info.node_ips.iter().copied().map(Address::Ip));
                addrs
            }
            scope::SecretScope::Pod => {
                let mut addrs = Vec::new();
                if let Some(svc_name) = &pod_info.service_name {
                    addrs.push(Address::Dns(format!(
                        "{}.{}.svc.cluster.local",
                        svc_name, self.namespace
                    )));
                    addrs.push(Address::Dns(format!(
                        "{}.{}.{}.svc.cluster.local",
                        self.pod, svc_name, self.namespace
                    )));
                }
                addrs.extend(pod_info.pod_ips.iter().copied().map(Address::Ip));
                addrs
            }
            scope::SecretScope::Service { name } => vec![Address::Dns(format!(
                "{}.{}.svc.cluster.local",
                name, self.namespace
            ))],
        }
    }
}

type SecretFiles = HashMap<PathBuf, Vec<u8>>;

#[derive(Default, Debug)]
pub struct SecretContents {
    pub files: SecretFiles,
    pub expires_after: Option<DateTime<FixedOffset>>,
}
impl SecretContents {
    fn new(files: SecretFiles) -> Self {
        Self {
            files,
            ..Self::default()
        }
    }

    fn expires_after(mut self, deadline: DateTime<FixedOffset>) -> Self {
        self.expires_after = Some(deadline);
        self
    }
}

/// This trait needs to be implemented by all secret providers.
/// It gets the pod information as well as volume definition and has to
/// return any number of files.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    type Error: SecretBackendError;

    async fn get_secret_data(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: pod_info::PodInfo,
    ) -> Result<SecretContents, Self::Error>;
}

pub trait SecretBackendError: std::error::Error + Send + Sync + 'static {
    fn grpc_code(&self) -> tonic::Code;
}

impl SecretBackendError for Infallible {
    fn grpc_code(&self) -> tonic::Code {
        match *self {}
    }
}
