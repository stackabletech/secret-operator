use std::{fmt::Display, ops::Deref};

use snafu::Snafu;
use stackable_operator::{
    k8s_openapi::api::core::v1::{ConfigMap, Secret},
    kube::api::PartialObjectMeta,
    schemars::{Schema, SchemaGenerator},
    shared::time::Duration,
};

use crate::{
    backend,
    crd::{
        KerberosPrincipal,
        v1alpha1::{
            ActiveDirectorySamAccountNameRules, AutoTlsBackend, AutoTlsCa, CertManagerBackend,
            CertificateKeyGeneration, SearchNamespace, SearchNamespaceMatchCondition,
            SecretClassBackend,
        },
    },
};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidKerberosPrincipal {
    #[snafu(display(
        "principal contains illegal characters (allowed: alphanumeric, /, @, -, _, and .)"
    ))]
    IllegalCharacter,

    #[snafu(display("principal may not start with a dash"))]
    StartWithDash,
}

impl SecretClassBackend {
    // Currently no `refers_to_*` method actually returns more than one element,
    // but returning `Iterator` instead of `Option` to ensure that all consumers are ready
    // for adding more conditions.

    // The matcher methods are on the CRD type rather than the initialized `Backend` impls
    // to avoid having to initialize the backend for each watch event.

    /// Returns the conditions where the backend refers to `config_map`.
    pub fn refers_to_config_map(
        &self,
        config_map: &PartialObjectMeta<ConfigMap>,
    ) -> impl Iterator<Item = SearchNamespaceMatchCondition> {
        let cm_namespace = config_map.metadata.namespace.as_deref();
        match self {
            Self::K8sSearch(backend) => {
                let name_matches = backend.trust_store_config_map_name == config_map.metadata.name;
                cm_namespace
                    .filter(|_| name_matches)
                    .and_then(|cm_ns| backend.search_namespace.matches_namespace(cm_ns))
            }
            Self::AutoTls(_) => None,
            Self::CertManager(_) => None,
            Self::KerberosKeytab(_) => None,
        }
        .into_iter()
    }

    /// Returns the conditions where the backend refers to `secret`.
    pub fn refers_to_secret(
        &self,
        secret: &PartialObjectMeta<Secret>,
    ) -> impl Iterator<Item = SearchNamespaceMatchCondition> {
        match self {
            Self::AutoTls(backend) => {
                (backend.ca.secret == *secret).then_some(SearchNamespaceMatchCondition::True)
            }
            Self::K8sSearch(_) => None,
            Self::CertManager(_) => None,
            Self::KerberosKeytab(_) => None,
        }
        .into_iter()
    }
}

impl SearchNamespace {
    pub fn resolve<'a>(&'a self, pod_namespace: &'a str) -> &'a str {
        match self {
            SearchNamespace::Pod {} => pod_namespace,
            SearchNamespace::Name(ns) => ns,
        }
    }

    /// Returns [`Some`] if this `SearchNamespace` could possibly match an object in the namespace
    /// `object_namespace`, otherwise [`None`].
    ///
    /// This is optimistic, you then need to call [`SearchNamespaceMatchCondition::matches_pod_namespace`]
    /// to evaluate the match for a specific pod's namespace.
    pub fn matches_namespace(
        &self,
        object_namespace: &str,
    ) -> Option<SearchNamespaceMatchCondition> {
        match self {
            SearchNamespace::Pod {} => Some(SearchNamespaceMatchCondition::IfPodIsInNamespace {
                namespace: object_namespace.to_string(),
            }),
            SearchNamespace::Name(ns) => {
                (ns == object_namespace).then_some(SearchNamespaceMatchCondition::True)
            }
        }
    }
}

impl SearchNamespaceMatchCondition {
    pub fn matches_pod_namespace(&self, pod_ns: &str) -> bool {
        match self {
            Self::True => true,
            Self::IfPodIsInNamespace { namespace } => namespace == pod_ns,
        }
    }
}

impl AutoTlsBackend {
    pub(crate) fn default_max_certificate_lifetime() -> Duration {
        backend::tls::DEFAULT_MAX_CERT_LIFETIME
    }
}

impl AutoTlsCa {
    pub(crate) fn default_ca_certificate_lifetime() -> Duration {
        backend::tls::DEFAULT_CA_CERT_LIFETIME
    }
}

impl CertificateKeyGeneration {
    pub const RSA_KEY_LENGTH_2048: u32 = 2048;
    pub const RSA_KEY_LENGTH_3072: u32 = 3072;
    pub const RSA_KEY_LENGTH_4096: u32 = 4096;

    // Could not get a "standard" enum with assigned values/discriminants to work as integers in the schema
    // The following was generated and requires the length to be provided as string (we want an integer)
    // keyGeneration:
    //   default:
    //     rsa:
    //       length: '2048'
    //   oneOf:
    //     - required:
    //         - rsa
    //   properties:
    //     rsa:
    //       properties:
    //         length:
    //           enum:
    //             - '2048'
    //             - '3072'
    //             - '4096'
    //           type: string
    pub fn tls_key_length_schema(_: &mut SchemaGenerator) -> Schema {
        serde_json::from_value(serde_json::json!({
            "type": "integer",
            "enum": [
                Self::RSA_KEY_LENGTH_2048,
                Self::RSA_KEY_LENGTH_3072,
                Self::RSA_KEY_LENGTH_4096
            ]
        }))
        .expect("Failed to parse JSON of custom tls key length schema")
    }
}

impl Default for CertificateKeyGeneration {
    fn default() -> Self {
        Self::Rsa {
            length: Self::RSA_KEY_LENGTH_2048,
        }
    }
}

impl CertManagerBackend {
    pub(crate) fn default_certificate_lifetime() -> Duration {
        backend::cert_manager::DEFAULT_CERT_LIFETIME
    }
}

impl ActiveDirectorySamAccountNameRules {
    pub(crate) fn default_total_length() -> u8 {
        // Default AD samAccountName length limit
        20
    }
}

impl TryFrom<String> for KerberosPrincipal {
    type Error = InvalidKerberosPrincipal;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with('-') {
            invalid_kerberos_principal::StartWithDashSnafu.fail()
        } else if value.contains(|chr: char| {
            !chr.is_alphanumeric()
                && chr != '/'
                && chr != '@'
                && chr != '.'
                && chr != '-'
                && chr != '_'
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
