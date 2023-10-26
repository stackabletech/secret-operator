use std::{fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    k8s_openapi::api::core::v1::SecretReference,
    kube::CustomResource,
    schemars::{self, JsonSchema},
    time::Duration,
};

use crate::backend::tls::DEFAULT_MAX_CERT_LIFETIME;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum SecretClassBackend {
    K8sSearch(K8sSearchBackend),
    AutoTls(AutoTlsBackend),
    KerberosKeytab(KerberosKeytabBackend),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct K8sSearchBackend {
    pub search_namespace: SearchNamespace,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SearchNamespace {
    Pod {},
    Name(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoTlsBackend {
    pub ca: AutoTlsCa,

    #[serde(default = "default_max_certificate_lifetime")]
    /// Maximum lifetime the created certificates are allowed to have.
    /// In case consumers request a longer lifetime than allowed by this setting,
    /// the lifetime will be the minimum of both, so this setting takes precedence.
    pub max_certificate_lifetime: Duration,
}

fn default_max_certificate_lifetime() -> Duration {
    DEFAULT_MAX_CERT_LIFETIME
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoTlsCa {
    pub secret: SecretReference,
    /// Whether a new certificate authority should be generated if it does not already exist
    #[serde(default)]
    pub auto_generate: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KerberosKeytabBackend {
    pub realm_name: Hostname,
    pub kdc: Hostname,
    pub admin: KerberosKeytabBackendAdmin,
    pub admin_keytab_secret: SecretReference,
    pub admin_principal: KerberosPrincipal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum KerberosKeytabBackendAdmin {
    #[serde(rename_all = "camelCase")]
    Mit { kadmin_server: Hostname },
    #[serde(rename_all = "camelCase")]
    ActiveDirectory {
        ldap_server: Hostname,
        ldap_tls_ca_secret: SecretReference,
        password_cache_secret: SecretReference,
        user_distinguished_name: String,
        schema_distinguished_name: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
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
impl Deref for Hostname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
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
impl Deref for KerberosPrincipal {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{
        backend::tls::DEFAULT_MAX_CERT_LIFETIME,
        crd::{AutoTlsBackend, SecretClass, SecretClassSpec},
    };

    #[test]
    fn test_deserialization() {
        let input: &str = r#"
        apiVersion: secrets.stackable.tech/v1alpha1
        kind: SecretClass
        metadata:
          name: tls
        spec:
          backend:
            autoTls:
              ca:
                secret:
                  name: secret-provisioner-tls-ca
                  namespace: default
        "#;
        let deserializer = serde_yaml::Deserializer::from_str(input);
        let secret_class: SecretClass =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
        assert_eq!(
            secret_class.spec,
            SecretClassSpec {
                backend: crate::crd::SecretClassBackend::AutoTls(AutoTlsBackend {
                    ca: crate::crd::AutoTlsCa {
                        secret: SecretReference {
                            name: Some("secret-provisioner-tls-ca".to_string()),
                            namespace: Some("default".to_string()),
                        },
                        auto_generate: false,
                    },
                    max_certificate_lifetime: DEFAULT_MAX_CERT_LIFETIME,
                })
            }
        );

        let input: &str = r#"
        apiVersion: secrets.stackable.tech/v1alpha1
        kind: SecretClass
        metadata:
          name: tls
        spec:
          backend:
            autoTls:
              ca:
                secret:
                  name: secret-provisioner-tls-ca
                  namespace: default
                autoGenerate: true
              maxCertificateLifetime: 31d
        "#;
        let deserializer = serde_yaml::Deserializer::from_str(input);
        let secret_class: SecretClass =
            serde_yaml::with::singleton_map_recursive::deserialize(deserializer).unwrap();
        assert_eq!(
            secret_class.spec,
            SecretClassSpec {
                backend: crate::crd::SecretClassBackend::AutoTls(AutoTlsBackend {
                    ca: crate::crd::AutoTlsCa {
                        secret: SecretReference {
                            name: Some("secret-provisioner-tls-ca".to_string()),
                            namespace: Some("default".to_string()),
                        },
                        auto_generate: true,
                    },
                    max_certificate_lifetime: Duration::from_days_unchecked(31),
                })
            }
        );
    }
}
