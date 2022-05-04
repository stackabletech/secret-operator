use serde::{Deserialize, Serialize};
use stackable_operator::k8s_openapi::api::core::v1::SecretReference;
use stackable_operator::kube::CustomResource;
use stackable_operator::schemars::{self, JsonSchema};

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "secrets.stackable.tech",
    version = "v1alpha1",
    kind = "SecretClass",
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct SecretClassSpec {
    pub backend: SecretClassBackend,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SecretClassBackend {
    K8sSearch(K8sSearchBackend),
    AutoTls(AutoTlsBackend),
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct K8sSearchBackend {
    pub search_namespace: SearchNamespace,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SearchNamespace {
    Pod {},
    Name(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoTlsBackend {
    pub ca: AutoTlsCa,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoTlsCa {
    pub secret: SecretReference,
    /// Whether a new certificate authority should be generated if it does not already exist
    #[serde(default)]
    pub auto_generate: bool,
}
