use std::{fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::{
    kube::CustomResource,
    schemars::{self, JsonSchema},
    time::Duration,
};
use stackable_secret_operator_crd_utils::SecretReference;

use crate::backend;

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
    /// A new certificate and keypair will be generated and signed for each Pod, keys or certificates are never reused.
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct K8sSearchBackend {
    /// Configures the namespace searched for Secret objects.
    pub search_namespace: SearchNamespace,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum SearchNamespace {
    /// The Secret objects are located in the same namespace as the Pod object.
    /// Should be used for Secrets that are provisioned by the application administrator.
    Pod {},

    /// The Secret objects are located in a single global namespace.
    /// Should be used for secrets that are provisioned by the cluster administrator.
    Name(String),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AutoTlsBackend {
    /// Configures the certificate authority used to issue Pod certificates.
    pub ca: AutoTlsCa,

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

    #[serde(default = "TlsKeyGeneration::default_tls_key_generation")]
    pub key_generation: TlsKeyGeneration,
}

impl AutoTlsCa {
    fn default_ca_certificate_lifetime() -> Duration {
        backend::tls::DEFAULT_CA_CERT_LIFETIME
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum TlsKeyGeneration {
    Rsa { length: TlsRsaKeyLength },
}

impl TlsKeyGeneration {
    fn default_tls_key_generation() -> Self {
        Self::Rsa {
            length: TlsRsaKeyLength::L4096,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
// Rust does not allow to start identifiers with numbers, thats why we use the L prefix for "length".
pub enum TlsRsaKeyLength {
    #[serde(rename = "2048")]
    L2048,
    #[serde(rename = "4096")]
    L4096,
    #[serde(rename = "8192")]
    L8192
}

impl TlsRsaKeyLength {
    pub fn as_bits(&self) -> u32 {
        match &self  {
            Self::L2048 => 2048,
            Self::L4096 => 4096,
            Self::L8192 => 8192
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
    pub realm_name: Hostname,

    /// The hostname of the Kerberos Key Distribution Center (KDC).
    /// This should be provided by the Kerberos administrator.
    pub kdc: Hostname,

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
        kadmin_server: Hostname,
    },

    /// Credentials should be provisioned in a Microsoft Active Directory domain.
    #[serde(rename_all = "camelCase")]
    ActiveDirectory {
        /// An AD LDAP server, such as the AD Domain Controller.
        /// This must match the server’s FQDN, or GSSAPI authentication will fail.
        ldap_server: Hostname,

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
                caCertificateLifetime: 100d
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
                        ca_certificate_lifetime: Duration::from_days_unchecked(100)
                    },
                    max_certificate_lifetime: Duration::from_days_unchecked(31),
                })
            }
        );
    }
}
