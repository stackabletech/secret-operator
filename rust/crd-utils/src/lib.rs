//! CRD types that are shared between secret-operator components, but aren't clearly owned by one of them.

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    k8s_openapi::api::core::v1::Secret,
    kube::runtime::reflector::ObjectRef,
    schemars::{self, JsonSchema},
};

// Redefine SecretReference instead of reusing k8s-openapi's, in order to make name/namespace mandatory.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretReference {
    /// Namespace of the Secret being referred to.
    pub namespace: String,
    /// Name of the Secret being referred to.
    pub name: String,
}

// Use ObjectRef for logging/errors
impl Display for SecretReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ObjectRef::<Secret>::from(self).fmt(f)
    }
}
impl From<SecretReference> for ObjectRef<Secret> {
    fn from(val: SecretReference) -> Self {
        ObjectRef::<Secret>::from(&val)
    }
}
impl From<&SecretReference> for ObjectRef<Secret> {
    fn from(val: &SecretReference) -> Self {
        ObjectRef::<Secret>::new(&val.name).within(&val.namespace)
    }
}
