pub mod dynamic;
pub mod k8s_search;
pub mod tls;

use async_trait::async_trait;
use serde::{de::IntoDeserializer, Deserialize, Deserializer};
use std::{borrow::Cow, collections::HashMap, convert::Infallible, path::PathBuf};

pub use dynamic::Dynamic;
pub use k8s_search::K8sSearch;
pub use tls::TlsGenerate;

#[derive(Deserialize, Clone, Copy)]
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
    fn scope_value<'a>(&'a self, node_info: &'a NodeInfo, scope: SecretScope) -> Cow<'a, str> {
        match scope {
            SecretScope::Node => Cow::Borrowed(&node_info.name),
            SecretScope::Pod => {
                Cow::Owned(format!("{}.{}.svc.cluster.local", self.pod, self.namespace))
            }
        }
    }
}

pub struct NodeInfo {
    pub name: String,
}

type SecretFiles = HashMap<PathBuf, Vec<u8>>;

#[async_trait]
pub trait SecretBackend: Send + Sync {
    type Error: SecretBackendError;

    async fn get_secret_data(
        &self,
        selector: SecretVolumeSelector,
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
