//! CRDs owned by [cert-manager](https://cert-manager.io/), see [their API docs](https://cert-manager.io/docs/reference/api-docs/).

use serde::{Deserialize, Serialize};
use stackable_operator::{
    k8s_openapi::apimachinery::pkg::apis::meta::v1::Time,
    kube::CustomResource,
    schemars::{self, JsonSchema},
};

/// See <https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.Certificate>.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "cert-manager.io",
    version = "v1",
    kind = "Certificate",
    namespaced,
    status = "CertificateStatus",
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSpec {
    pub secret_name: String,
    pub duration: Option<String>,
    #[serde(default)]
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    pub issuer_ref: ObjectReference,
    pub private_key: CertificatePrivateKey,
}

/// See <https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.CertificateStatus>.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificateStatus {
    /// When cert-manager will next attempt to renew the certificate.
    pub renewal_time: Option<Time>,
}

/// See <https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.CertificatePrivateKey>.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertificatePrivateKey {
    pub algorithm: String,
    pub size: u32,
}

/// See <https://cert-manager.io/docs/reference/api-docs/#meta.cert-manager.io/v1.ObjectReference>.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ObjectReference {
    pub name: String,
    pub kind: Option<String>,
}
