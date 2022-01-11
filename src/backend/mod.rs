pub mod dynamic;
pub mod k8s_search;
pub mod pod_info;
pub mod scope;
pub mod tls;

use async_trait::async_trait;
use serde::Deserialize;
use std::{collections::HashMap, convert::Infallible, path::PathBuf};

pub use dynamic::Dynamic;
pub use k8s_search::K8sSearch;
pub use tls::TlsGenerate;

use pod_info::Address;
use scope::SecretScope;

#[derive(Deserialize)]
pub struct SecretVolumeSelector {
    #[serde(rename = "secrets.stackable.tech/type")]
    pub ty: String,
    #[serde(
        rename = "secrets.stackable.tech/scope",
        default,
        deserialize_with = "SecretScope::deserialize_vec"
    )]
    pub scope: Vec<scope::SecretScope>,
    #[serde(rename = "csi.storage.k8s.io/pod.name")]
    pub pod: String,
    #[serde(rename = "csi.storage.k8s.io/pod.namespace")]
    pub namespace: String,
}

impl SecretVolumeSelector {
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

#[async_trait]
pub trait SecretBackend: Send + Sync {
    type Error: SecretBackendError;

    async fn get_secret_data(
        &self,
        selector: SecretVolumeSelector,
        pod_info: pod_info::PodInfo,
    ) -> Result<SecretFiles, Self::Error>;
}

pub trait SecretBackendError: std::error::Error + Send + Sync + 'static {
    fn grpc_code(&self) -> tonic::Code;
}

impl SecretBackendError for Infallible {
    fn grpc_code(&self) -> tonic::Code {
        match *self {}
    }
}
