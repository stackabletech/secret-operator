//! CRD types that are shared between secret-operator components, but aren't clearly owned by one of them.

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use stackable_operator::{
    k8s_openapi::api::core::v1::{ConfigMap, Secret},
    kube::{
        api::{DynamicObject, ObjectMeta, PartialObjectMeta},
        runtime::reflector::ObjectRef,
    },
    schemars::{self, JsonSchema},
};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigMapReference {
    /// Namespace of the ConfigMap being referred to.
    pub namespace: String,
    /// Name of the ConfigMap being referred to.
    pub name: String,
}

// Use ObjectRef for logging/errors
impl Display for ConfigMapReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ObjectRef::<ConfigMap>::from(self).fmt(f)
    }
}
impl From<ConfigMapReference> for ObjectRef<ConfigMap> {
    fn from(val: ConfigMapReference) -> Self {
        ObjectRef::<ConfigMap>::from(&val)
    }
}
impl From<&ConfigMapReference> for ObjectRef<ConfigMap> {
    fn from(val: &ConfigMapReference) -> Self {
        ObjectRef::<ConfigMap>::new(&val.name).within(&val.namespace)
    }
}
impl From<ConfigMapReference> for ObjectRef<DynamicObject> {
    fn from(val: ConfigMapReference) -> Self {
        ObjectRef::<ConfigMap>::from(&val).erase()
    }
}
impl From<&ConfigMapReference> for ObjectRef<DynamicObject> {
    fn from(val: &ConfigMapReference) -> Self {
        ObjectRef::<ConfigMap>::from(val).erase()
    }
}

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
impl From<SecretReference> for ObjectRef<DynamicObject> {
    fn from(val: SecretReference) -> Self {
        ObjectRef::<Secret>::from(&val).erase()
    }
}
impl From<&SecretReference> for ObjectRef<DynamicObject> {
    fn from(val: &SecretReference) -> Self {
        ObjectRef::<Secret>::from(val).erase()
    }
}

impl SecretReference {
    fn matches(&self, secret_meta: &ObjectMeta) -> bool {
        secret_meta.name.as_deref() == Some(&self.name)
            && secret_meta.namespace.as_deref() == Some(&self.namespace)
    }
}
impl PartialEq<Secret> for SecretReference {
    fn eq(&self, secret: &Secret) -> bool {
        self.matches(&secret.metadata)
    }
}
impl PartialEq<PartialObjectMeta<Secret>> for SecretReference {
    fn eq(&self, secret: &PartialObjectMeta<Secret>) -> bool {
        self.matches(&secret.metadata)
    }
}
