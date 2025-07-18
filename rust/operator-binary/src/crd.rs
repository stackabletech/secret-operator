use std::{fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    commons::networking::{HostName, KerberosRealmName},
    k8s_openapi::api::core::v1::{ConfigMap, Secret},
    kube::{CustomResource, api::PartialObjectMeta},
    schemars::{self, JsonSchema, schema::Schema},
    time::Duration,
};
use stackable_secret_operator_crd_utils::{ConfigMapReference, SecretReference};

use crate::{backend, format::SecretFormat};

/// A [SecretClass](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass) is a cluster-global Kubernetes resource
/// that defines a category of secrets that the Secret Operator knows how to provision.
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
    /// Each SecretClass is associated with a single
    /// [backend](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass#backend),
    /// which dictates the mechanism for issuing that kind of Secret.
    pub backend: SecretClassBackend,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[allow(clippy::large_enum_variant)]
pub enum SecretClassBackend {
    /// The [`k8sSearch` backend](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass#backend-k8ssearch)
    /// can be used to mount Secrets across namespaces into Pods.
    K8sSearch(K8sSearchBackend),

    /// The [`autoTls` backend](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass#backend-autotls)
    /// issues a TLS certificate signed by the Secret Operator.
    /// The certificate authority can be provided by the administrator, or managed automatically by the Secret Operator.
    ///
    /// A new certificate and key pair will be generated and signed for each Pod, keys or certificates are never reused.
    AutoTls(AutoTlsBackend),

    /// The [`experimentalCertManager` backend][1] injects a TLS certificate issued
    /// by [cert-manager](https://cert-manager.io/).
    ///
    /// A new certificate will be requested the first time it is used by a Pod, it
    /// will be reused after that (subject to cert-manager renewal rules).
    ///
    /// [1]: DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass#backend-certmanager
    #[serde(rename = "experimentalCertManager")]
    CertManager(CertManagerBackend),

    /// The [`kerberosKeytab` backend](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass#backend-kerberoskeytab)
    /// creates a Kerberos keytab file for a selected realm.
    /// The Kerberos KDC and administrator credentials must be provided by the administrator.
    KerberosKeytab(KerberosKeytabBackend),
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct K8sSearchBackend {
    /// Configures the namespace searched for Secret objects.
    pub search_namespace: SearchNamespace,

    /// Name of a ConfigMap that contains the information required to validate against this SecretClass.
    ///
    /// Resolved relative to `search_namespace`.
    ///
    /// Required to request a TrustStore for this SecretClass.
    pub trust_store_config_map_name: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SearchNamespace {
    /// The Secret objects are located in the same namespace as the Pod object.
    /// Should be used for Secrets that are provisioned by the application administrator.
    Pod {},

    /// The Secret objects are located in a single global namespace.
    /// Should be used for secrets that are provisioned by the cluster administrator.
    Name(String),
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

/// A partially evaluated match returned by [`SearchNamespace::matches_namespace`].
/// Use [`Self::matches_pod_namespace`] to evaluate fully.
#[derive(Debug)]
pub enum SearchNamespaceMatchCondition {
    /// The target object matches the search namespace.
    True,

    /// The target object only matches the search namespace if mounted into a pod in
    /// `namespace`.
    IfPodIsInNamespace { namespace: String },
}

impl SearchNamespaceMatchCondition {
    pub fn matches_pod_namespace(&self, pod_ns: &str) -> bool {
        match self {
            Self::True => true,
            Self::IfPodIsInNamespace { namespace } => namespace == pod_ns,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoTlsBackend {
    /// Configures the certificate authority used to issue Pod certificates.
    pub ca: AutoTlsCa,

    /// Additional trust roots which are added to the provided `ca.crt` file.
    #[serde(default)]
    pub additional_trust_roots: Vec<AdditionalTrustRoot>,

    /// Maximum lifetime the created certificates are allowed to have.
    /// In case consumers request a longer lifetime than allowed by this setting,
    /// the lifetime will be the minimum of both, so this setting takes precedence.
    /// The default value is 15 days.
    #[serde(default = "AutoTlsBackend::default_max_certificate_lifetime")]
    pub max_certificate_lifetime: Duration,
}

impl AutoTlsBackend {
    fn default_max_certificate_lifetime() -> Duration {
        backend::tls::DEFAULT_MAX_CERT_LIFETIME
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoTlsCa {
    /// Reference (name and namespace) to a Kubernetes Secret object where the CA certificate
    /// and key is stored in the keys `ca.crt` and `ca.key` respectively.
    pub secret: SecretReference,

    /// Whether the certificate authority should be managed by Secret Operator, including being generated
    /// if it does not already exist.
    // TODO: Consider renaming to `manage` for v1alpha2
    #[serde(default)]
    pub auto_generate: bool,

    /// The lifetime of each generated certificate authority.
    ///
    /// Should always be more than double `maxCertificateLifetime`.
    ///
    /// If `autoGenerate: true` then the Secret Operator will prepare a new CA certificate the old CA approaches expiration.
    /// If `autoGenerate: false` then the Secret Operator will log a warning instead.
    #[serde(default = "AutoTlsCa::default_ca_certificate_lifetime")]
    pub ca_certificate_lifetime: Duration,

    /// The algorithm used to generate a key pair and required configuration settings.
    /// Currently only RSA and a key length of 2048, 3072 or 4096 bits can be configured.
    #[serde(default)]
    pub key_generation: CertificateKeyGeneration,
}

impl AutoTlsCa {
    fn default_ca_certificate_lifetime() -> Duration {
        backend::tls::DEFAULT_CA_CERT_LIFETIME
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum AdditionalTrustRoot {
    /// Reference (name and namespace) to a Kubernetes ConfigMap object where additional
    /// certificates are stored.
    /// The extensions of the keys denote its contents: A key suffixed with `.crt` contains a stack
    /// of base64 encoded DER certificates, a key suffixed with `.der` contains a binary DER
    /// certificate.
    ConfigMap(ConfigMapReference),

    /// Reference (name and namespace) to a Kubernetes Secret object where additional certificates
    /// are stored.
    /// The extensions of the keys denote its contents: A key suffixed with `.crt` contains a stack
    /// of base64 encoded DER certificates, a key suffixed with `.der` contains a binary DER
    /// certificate.
    Secret(SecretReference),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CertificateKeyGeneration {
    Rsa {
        /// The amount of bits used for generating the RSA keypair.
        /// Currently, `2048`, `3072` and `4096` are supported. Defaults to `2048` bits.
        #[schemars(schema_with = "CertificateKeyGeneration::tls_key_length_schema")]
        length: u32,
    },
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
    pub fn tls_key_length_schema(_: &mut schemars::gen::SchemaGenerator) -> Schema {
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertManagerBackend {
    /// A reference to the cert-manager issuer that the certificates should be requested from.
    pub issuer: CertManagerIssuer,

    /// The default lifetime of certificates.
    ///
    /// Defaults to 1 day. This may need to be increased for external issuers that impose rate limits (such as Let's Encrypt).
    #[serde(default = "CertManagerBackend::default_certificate_lifetime")]
    pub default_certificate_lifetime: Duration,

    /// The algorithm used to generate a key pair and required configuration settings.
    /// Currently only RSA and a key length of 2048, 3072 or 4096 bits can be configured.
    #[serde(default)]
    pub key_generation: CertificateKeyGeneration,
}

impl CertManagerBackend {
    fn default_certificate_lifetime() -> Duration {
        backend::cert_manager::DEFAULT_CERT_LIFETIME
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CertManagerIssuer {
    /// The kind of the issuer, Issuer or ClusterIssuer.
    ///
    /// If Issuer then it must be in the same namespace as the Pods using it.
    pub kind: CertManagerIssuerKind,

    /// The name of the issuer.
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, JsonSchema, strum::Display)]
pub enum CertManagerIssuerKind {
    /// An [Issuer](https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.Issuer) in the same namespace as the Pod.
    Issuer,

    /// A cluster-scoped [ClusterIssuer](https://cert-manager.io/docs/reference/api-docs/#cert-manager.io/v1.ClusterIssuer).
    ClusterIssuer,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KerberosKeytabBackend {
    /// The name of the Kerberos realm. This should be provided by the Kerberos administrator.
    pub realm_name: KerberosRealmName,

    /// The hostname of the Kerberos Key Distribution Center (KDC).
    /// This should be provided by the Kerberos administrator.
    pub kdc: HostName,

    /// Kerberos admin configuration settings.
    pub admin: KerberosKeytabBackendAdmin,

    /// Reference (`name` and `namespace`) to a K8s Secret object where a
    /// keytab with administrative privileges is stored in the key `keytab`.
    pub admin_keytab_secret: SecretReference,

    /// The admin principal.
    pub admin_principal: KerberosPrincipal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum KerberosKeytabBackendAdmin {
    /// Credentials should be provisioned in a MIT Kerberos Admin Server.
    #[serde(rename_all = "camelCase")]
    Mit {
        /// The hostname of the Kerberos Admin Server.
        /// This should be provided by the Kerberos administrator.
        kadmin_server: HostName,
    },

    /// Credentials should be provisioned in a Microsoft Active Directory domain.
    #[serde(rename_all = "camelCase")]
    ActiveDirectory {
        /// An AD LDAP server, such as the AD Domain Controller.
        /// This must match the server’s FQDN, or GSSAPI authentication will fail.
        ldap_server: HostName,

        /// Reference (name and namespace) to a Kubernetes Secret object containing
        /// the TLS CA (in `ca.crt`) that the LDAP server’s certificate should be authenticated against.
        ldap_tls_ca_secret: SecretReference,

        /// Reference (name and namespace) to a Kubernetes Secret object where workload
        /// passwords will be stored. This must not be accessible to end users.
        password_cache_secret: SecretReference,

        /// The root Distinguished Name (DN) where service accounts should be provisioned,
        /// typically `CN=Users,{domain_dn}`.
        user_distinguished_name: String,

        /// The root Distinguished Name (DN) for AD-managed schemas,
        /// typically `CN=Schema,CN=Configuration,{domain_dn}`.
        schema_distinguished_name: String,

        /// Allows samAccountName generation for new accounts to be customized.
        /// Note that setting this field (even if empty) makes the Secret Operator take
        /// over the generation duty from the domain controller.
        #[serde(rename = "experimentalGenerateSamAccountName")]
        generate_sam_account_name: Option<ActiveDirectorySamAccountNameRules>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ActiveDirectorySamAccountNameRules {
    /// A prefix to be prepended to generated samAccountNames.
    #[serde(default)]
    pub prefix: String,
    /// The total length of generated samAccountNames, _including_ `prefix`.
    /// Must be larger than the length of `prefix`, but at most `20`.
    ///
    /// Note that this should be as large as possible, to minimize the risk of collisions.
    #[serde(default = "ActiveDirectorySamAccountNameRules::default_total_length")]
    pub total_length: u8,
}

impl ActiveDirectorySamAccountNameRules {
    fn default_total_length() -> u8 {
        // Default AD samAccountName length limit
        20
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct KerberosPrincipal(String);
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

/// A [TrustStore](DOCS_BASE_URL_PLACEHOLDER/secret-operator/truststore) requests information about how to
/// validate secrets issued by a [SecretClass](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass).
///
/// The requested information is written to a ConfigMap with the same name as the TrustStore.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "secrets.stackable.tech",
    version = "v1alpha1",
    kind = "TrustStore",
    namespaced,
    crates(
        kube_core = "stackable_operator::kube::core",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars"
    )
)]
#[serde(rename_all = "camelCase")]
pub struct TrustStoreSpec {
    /// The name of the SecretClass that the request concerns.
    pub secret_class_name: String,

    /// The [format](DOCS_BASE_URL_PLACEHOLDER/secret-operator/secretclass#format) that the data should be converted into.
    pub format: Option<SecretFormat>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        backend::tls::{DEFAULT_CA_CERT_LIFETIME, DEFAULT_MAX_CERT_LIFETIME},
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
                keyGeneration:
                  rsa:
                    length: 3072
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
                            name: "secret-provisioner-tls-ca".to_string(),
                            namespace: "default".to_string(),
                        },
                        auto_generate: false,
                        ca_certificate_lifetime: DEFAULT_CA_CERT_LIFETIME,
                        key_generation: CertificateKeyGeneration::Rsa {
                            length: CertificateKeyGeneration::RSA_KEY_LENGTH_3072
                        }
                    },
                    additional_trust_roots: vec![],
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
                caCertificateLifetime: 100d
              additionalTrustRoots:
                - configMap:
                    name: tls-root-ca-config-map
                    namespace: default
                - secret:
                    name: tls-root-ca-secret
                    namespace: default
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
                            name: "secret-provisioner-tls-ca".to_string(),
                            namespace: "default".to_string(),
                        },
                        auto_generate: true,
                        ca_certificate_lifetime: Duration::from_days_unchecked(100),
                        key_generation: CertificateKeyGeneration::default()
                    },
                    additional_trust_roots: vec![
                        AdditionalTrustRoot::ConfigMap(ConfigMapReference {
                            name: "tls-root-ca-config-map".to_string(),
                            namespace: "default".to_string(),
                        }),
                        AdditionalTrustRoot::Secret(SecretReference {
                            name: "tls-root-ca-secret".to_string(),
                            namespace: "default".to_string(),
                        })
                    ],
                    max_certificate_lifetime: Duration::from_days_unchecked(31),
                })
            }
        );
    }
}
