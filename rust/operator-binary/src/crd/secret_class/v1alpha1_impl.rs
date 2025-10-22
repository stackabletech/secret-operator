use stackable_operator::{
    k8s_openapi::api::core::v1::{ConfigMap, Secret},
    kube::api::PartialObjectMeta,
    schemars::{Schema, SchemaGenerator},
};

use crate::crd::secret_class::v1alpha1::{
    CertificateKeyGeneration, SearchNamespace, SearchNamespaceMatchCondition, SecretClassBackend,
};

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
            Self::ExperimentalCertManager(_) => None,
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
            Self::ExperimentalCertManager(_) => None,
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
