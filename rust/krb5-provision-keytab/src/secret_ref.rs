use std::fmt::Display;

use snafu::{OptionExt, Snafu};
use stackable_operator::{
    k8s_openapi::api::core::v1::{Secret, SecretReference},
    kube::runtime::reflector::ObjectRef,
};

#[derive(Debug, Snafu)]
#[snafu(display("secret ref is missing {field}"))]
pub struct IncompleteSecretRef {
    field: String,
}
#[derive(Debug, Clone)]
pub struct FullSecretRef {
    pub name: String,
    pub namespace: String,
}
impl TryFrom<SecretReference> for FullSecretRef {
    type Error = IncompleteSecretRef;

    fn try_from(secret_ref: SecretReference) -> Result<Self, IncompleteSecretRef> {
        Ok(Self {
            name: secret_ref
                .name
                .context(IncompleteSecretRefSnafu { field: "name" })?,
            namespace: secret_ref
                .namespace
                .context(IncompleteSecretRefSnafu { field: "namespace" })?,
        })
    }
}
impl From<&FullSecretRef> for FullSecretRef {
    fn from(pcr: &FullSecretRef) -> Self {
        pcr.clone()
    }
}
impl Display for FullSecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ObjectRef::<Secret>::new(&self.name)
            .within(&self.namespace)
            .fmt(f)
    }
}
