use serde::{Deserialize, Serialize};
use stackable_operator::{
    kube::CustomResource,
    schemars::{self, JsonSchema},
    versioned::versioned,
};

use crate::format::{SecretFormat, well_known::FILE_PEM_CERT_CA};

#[versioned(
    version(name = "v1alpha1"),
    version(name = "v1alpha2"),
    crates(
        kube_core = "stackable_operator::kube::core",
        kube_client = "stackable_operator::kube::client",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned"
    ),
    options(k8s(experimental_conversion_tracking))
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
        #[versioned(
            changed(since = "v1alpha2", from_type = "Option<SecretFormat>",),
            hint(option)
        )]
        pub format: Option<TrustStoreFormat>,
    }

    #[derive(Clone, Debug, PartialEq, JsonSchema, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub enum TrustStoreFormat {
        #[serde(rename_all = "camelCase")]
        TlsPem {
            /// Name of the key in the ConfigMap/Secret, in which the PEM encoded CA certificate should be placed.
            ///
            /// Defaults to `ca.crt`.
            #[serde(default = "default_tls_pem_ca_name")]
            ca_file_name: String,
        },
        TlsPkcs12 {},
        Kerberos {},
    }

    #[derive(Clone, Debug, Default, PartialEq, JsonSchema, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub enum TrustStoreOutputType {
        Secret,

        #[default]
        ConfigMap,
    }
}

fn default_tls_pem_ca_name() -> String {
    FILE_PEM_CERT_CA.to_owned()
}

impl From<SecretFormat> for v1alpha2::TrustStoreFormat {
    fn from(value: SecretFormat) -> Self {
        match value {
            SecretFormat::TlsPem => Self::TlsPem {
                ca_file_name: default_tls_pem_ca_name(),
            },
            SecretFormat::TlsPkcs12 => Self::TlsPkcs12 {},
            SecretFormat::Kerberos => Self::Kerberos {},
        }
    }
}

impl From<v1alpha2::TrustStoreFormat> for SecretFormat {
    fn from(value: v1alpha2::TrustStoreFormat) -> Self {
        match value {
            v1alpha2::TrustStoreFormat::TlsPem { .. } => Self::TlsPem,
            v1alpha2::TrustStoreFormat::TlsPkcs12 {} => Self::TlsPkcs12,
            v1alpha2::TrustStoreFormat::Kerberos {} => Self::Kerberos,
        }
    }
}

#[cfg(test)]
impl stackable_operator::versioned::test_utils::RoundtripTestData for v1alpha1::TrustStoreSpec {
    fn roundtrip_test_data() -> Vec<Self> {
        stackable_operator::utils::yaml_from_str_singleton_map(indoc::indoc! {"
          - secretClassName: tls
          - secretClassName: tls
            targetKind: ConfigMap
          - secretClassName: tls
            format: tls-pem
          - secretClassName: tls
            format: tls-pkcs12
          - secretClassName: tls
            format: kerberos
        "})
        .expect("Failed to parse SecretClassSpec YAML")
    }
}

#[cfg(test)]
impl stackable_operator::versioned::test_utils::RoundtripTestData for v1alpha2::TrustStoreSpec {
    fn roundtrip_test_data() -> Vec<Self> {
        stackable_operator::utils::yaml_from_str_singleton_map(indoc::indoc! {"
          - secretClassName: tls
          - secretClassName: tls
            targetKind: ConfigMap
          - secretClassName: tls
            format:
              tlsPem: {}
          - secretClassName: tls
            format:
              tlsPem:
                caFileName: ca.crt # default value
          - secretClassName: tls
            format:
              tlsPem:
                caFileName: my-ca.crt # custom value
          - secretClassName: tls
            format:
              tlsPkcs12: {}
          - secretClassName: tls
            format:
              kerberos: {}
        "})
        .expect("Failed to parse SecretClassSpec YAML")
    }
}
