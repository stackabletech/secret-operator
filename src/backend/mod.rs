pub mod k8s_search;

use async_trait::async_trait;
use serde::{de::IntoDeserializer, Deserialize, Deserializer};
use std::{collections::HashMap, path::PathBuf};

pub use k8s_search::K8sSearch;

#[derive(Deserialize)]
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

#[async_trait]
pub trait SecretBackend {
    type Error: SecretBackendError;

    async fn get_secret_data(
        &self,
        selector: SecretVolumeSelector,
    ) -> Result<HashMap<PathBuf, Vec<u8>>, Self::Error>;
}

pub trait SecretBackendError: std::error::Error {
    fn grpc_code(&self) -> tonic::Code;
}
