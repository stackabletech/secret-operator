use std::{ffi::OsStr, fmt::Display};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    k8s_openapi::api::core::v1::SecretReference,
    kube::CustomResource,
    schemars::{self, JsonSchema},
};

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
    KerberosKeytab(KerberosKeytabBackend),
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

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KerberosKeytabBackend {
    pub realm_name: Hostname,
    pub kdc: Hostname,
    pub admin_server: Hostname,
    pub admin_keytab_secret: SecretReference,
    pub admin_principal: KerberosPrincipal,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct Hostname(String);
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidHostname {
    #[snafu(display("hostname contains illegal characters (allowed: alphanumeric, -, and .)"))]
    IllegalCharacter,
    #[snafu(display("hostname may not start with a dash"))]
    StartWithDash,
}
impl TryFrom<String> for Hostname {
    type Error = InvalidHostname;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with('-') {
            invalid_hostname::StartWithDashSnafu.fail()
        } else if value.contains(|chr: char| !chr.is_alphanumeric() && chr != '.' && chr != '-') {
            invalid_hostname::IllegalCharacterSnafu.fail()
        } else {
            Ok(Hostname(value))
        }
    }
}
impl From<Hostname> for String {
    fn from(value: Hostname) -> Self {
        value.0
    }
}
impl Display for Hostname {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct KerberosPrincipal(String);
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidKerberosPrincipal {
    #[snafu(display(
        "principal contains illegal characters (allowed: alphanumeric, /, @, -, and .)"
    ))]
    IllegalCharacter,
    #[snafu(display("principal may not start with a dash"))]
    StartWithDash,
}
impl TryFrom<String> for KerberosPrincipal {
    type Error = InvalidKerberosPrincipal;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with('-') {
            invalid_kerberos_principal::StartWithDashSnafu.fail()
        } else if value.contains(|chr: char| {
            !chr.is_alphanumeric() && chr != '/' && chr != '@' && chr != '.' && chr != '-'
        }) {
            invalid_kerberos_principal::IllegalCharacterSnafu.fail()
        } else {
            Ok(KerberosPrincipal(value))
        }
    }
}
impl From<KerberosPrincipal> for String {
    fn from(value: KerberosPrincipal) -> Self {
        value.0
    }
}
impl Display for KerberosPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl AsRef<OsStr> for KerberosPrincipal {
    fn as_ref(&self) -> &OsStr {
        self.0.as_ref()
    }
}
