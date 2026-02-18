use serde::{Deserialize, Serialize};
use stackable_operator::{
    kube::CustomResource,
    schemars::{self, JsonSchema},
    versioned::versioned,
};

use crate::format::{SecretFormat, well_known::FILE_PEM_CERT_CA};

#[versioned(
    version(name = "v1alpha1"),
    crates(
        kube_core = "stackable_operator::kube::core",
        kube_client = "stackable_operator::kube::client",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned"
    )
)]
pub mod versioned {
    /// A [TrustStore](DOCS_BASE_URL_PLACEHOLDER/secret-operator/truststore) requests information about how to
    /// validate secrets issued by a [SecretClass](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass).
    ///
    /// The requested information is written to a ConfigMap with the same name as the TrustStore.
    #[versioned(crd(group = "secrets.stackable.tech", namespaced))]
    #[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
    #[serde(rename_all = "camelCase")]
    pub struct TrustStoreSpec {
        /// The name of the SecretClass that the request concerns.
        pub secret_class_name: String,

        /// Which Kubernetes kind should be used to output the requested information to.
        ///
        /// The trust information (such as a `ca.crt`) can be considered public information, so we put
        /// it in a `ConfigMap` by default. However, some tools might require it to be placed in a
        /// `Secret`, so we also support that.
        ///
        /// Can be either `ConfigMap` or `Secret`, defaults to `ConfigMap`.
        #[serde(default)]
        pub target_kind: TrustStoreOutputType,

        /// The [format](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass#format) that the data should be converted into.
        pub format: Option<SecretFormat>,

        /// Name of the key in the ConfigMap/Secret, in which the PEM encoded CA certificate should be placed.
        ///
        /// Only takes effect in case the `format` is `tls-pem`.
        /// Defaults to `ca.crt`.
        #[serde(default = "TrustStoreSpec::default_tls_pem_ca_name")]
        pub tls_pem_ca_name: String,
    }

    #[derive(Clone, Debug, Default, PartialEq, JsonSchema, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub enum TrustStoreOutputType {
        Secret,

        #[default]
        ConfigMap,
    }
}

impl v1alpha1::TrustStoreSpec {
    fn default_tls_pem_ca_name() -> String {
        FILE_PEM_CERT_CA.to_owned()
    }
}
