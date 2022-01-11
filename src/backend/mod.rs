pub mod dynamic;
pub mod k8s_search;
pub mod pod_info;
pub mod tls;

use async_trait::async_trait;
use serde::{de::IntoDeserializer, Deserialize, Deserializer};
use std::{collections::HashMap, convert::Infallible, path::PathBuf};

pub use dynamic::Dynamic;
pub use k8s_search::K8sSearch;
pub use tls::TlsGenerate;

use self::pod_info::Address;

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(rename_all = "camelCase")]
pub enum SecretScope {
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

#[derive(Deserialize)]
pub struct SecretVolumeSelector {
    #[serde(rename = "secrets.stackable.tech/type")]
    pub ty: String,
    #[serde(
        rename = "secrets.stackable.tech/scope",
        default,
        deserialize_with = "SecretScope::deserialize_vec"
    )]
    pub scope: Vec<SecretScope>,
    #[serde(rename = "csi.storage.k8s.io/pod.name")]
    pub pod: String,
    #[serde(rename = "csi.storage.k8s.io/pod.namespace")]
    pub namespace: String,
}

impl SecretVolumeSelector {
    fn scope_addresses<'a>(
        &'a self,
        pod_info: &'a pod_info::PodInfo,
        scope: SecretScope,
    ) -> Vec<pod_info::Address> {
        match scope {
            SecretScope::Node => {
                let mut addrs = vec![Address::Dns(pod_info.node_name.clone())];
                addrs.extend(pod_info.node_ips.iter().copied().map(pod_info::Address::Ip));
                addrs
            }
            SecretScope::Pod => {
                let mut addrs = Vec::new();
                if let Some(svc_name) = &pod_info.service_name {
                    addrs.push(pod_info::Address::Dns(format!(
                        "{}.{}.svc.cluster.local",
                        svc_name, self.namespace
                    )));
                    addrs.push(pod_info::Address::Dns(format!(
                        "{}.{}.{}.svc.cluster.local",
                        self.pod, svc_name, self.namespace
                    )));
                }
                addrs.extend(pod_info.pod_ips.iter().copied().map(pod_info::Address::Ip));
                addrs
            }
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
