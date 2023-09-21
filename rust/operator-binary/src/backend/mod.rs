//! Collects or generates secret data based on the request in the Kubernetes `Volume` definition

pub mod dynamic;
pub mod k8s_search;
pub mod kerberos_keytab;
pub mod pod_info;
pub mod scope;
pub mod tls;

use async_trait::async_trait;
use serde::{Deserialize, Deserializer};
use stackable_operator::{
    duration::Duration,
    k8s_openapi::chrono::{DateTime, FixedOffset},
};
use std::{collections::HashSet, convert::Infallible};

pub use dynamic::Dynamic;
pub use k8s_search::K8sSearch;
pub use kerberos_keytab::KerberosKeytab;
pub use tls::TlsGenerate;

use pod_info::Address;
use scope::SecretScope;

use crate::format::{SecretData, SecretFormat};

use self::tls::{DEFAULT_CERT_LIFETIME, DEFAULT_CERT_RESTART_BUFFER};

/// Configuration provided by the `Volume` selecting what secret data should be provided
///
/// Fields beginning with `csi.storage.k8s.io/` are provided by the Kubelet
#[derive(Deserialize, Debug)]
pub struct SecretVolumeSelector {
    /// What kind of secret should be used
    #[serde(rename = "secrets.stackable.tech/class")]
    pub class: String,
    /// Scopes define what the secret identifies about a pod
    ///
    /// Currently supported scopes:
    /// - `pod` - The name and address of the pod itself
    /// - `node` - The Kubernetes `Node` that the pod is running on
    /// - `service` - A Kubernetes `Service` that the pod is participating in, this takes the name of the service in the format `service=foo`
    ///
    /// Multiple scopes are supported, these should be provided in a comma-separated list (for example: `pod,node`)
    #[serde(
        rename = "secrets.stackable.tech/scope",
        default,
        deserialize_with = "SecretScope::deserialize_vec"
    )]
    pub scope: Vec<scope::SecretScope>,
    /// The name of the `Pod`, provided by Kubelet
    #[serde(rename = "csi.storage.k8s.io/pod.name")]
    pub pod: String,
    /// The name of the `Pod`'s `Namespace`, provided by Kubelet
    #[serde(rename = "csi.storage.k8s.io/pod.namespace")]
    pub namespace: String,
    /// The desired format of the mounted secrets
    ///
    /// Currently supported formats:
    /// - `tls-pem` - A Kubernetes-style triple of PEM-encoded certificate files (`tls.crt`, `tls.key`, `ca.crt`).
    /// - `tls-pkcs12` - A PKCS#12 key store named `keystore.p12` and truststore named `truststore.p12`.
    /// - `kerberos` - A Kerberos keytab named `keytab`, along with a `krb5.conf`.
    ///
    /// Defaults to passing through the native format of the secret backend.
    #[serde(
        rename = "secrets.stackable.tech/format",
        deserialize_with = "SecretVolumeSelector::deserialize_some",
        default
    )]
    pub format: Option<SecretFormat>,

    /// The Kerberos service names (`SERVICE_NAME/hostname@realm`)
    #[serde(
        rename = "secrets.stackable.tech/kerberos.service.names",
        deserialize_with = "SecretVolumeSelector::deserialize_str_vec",
        default = "SecretVolumeSelector::default_kerberos_service_names"
    )]
    pub kerberos_service_names: Vec<String>,

    /// The password used to encrypt the TLS PKCS#12 keystore
    ///
    /// Required for some applications that misbehave with blank keystore passwords (such as Hadoop).
    /// Has no effect if `format` is not `tls-pkcs12`.
    #[serde(
        rename = "secrets.stackable.tech/format.compatibility.tls-pkcs12.password",
        deserialize_with = "SecretVolumeSelector::deserialize_some",
        default
    )]
    pub compat_tls_pkcs12_password: Option<String>,

    /// The TLS cert lifetime (`1d`, `7d`, `1m` or `1y`).
    #[serde(
        rename = "secrets.stackable.tech/backend.autotls.cert.lifetime",
        default = "default_cert_lifetime"
    )]
    pub autotls_cert_lifetime: Duration,

    /// The amount of time the Pod using the cert gets restarted before the cert expires.
    /// Keep in mind that there can be multiple Pods - such as 80 datanodes - trying to
    /// shut down at the same time. It can take some hours until all Pods are restarted
    /// in a rolling fashion.
    /// Format is `1d`, `7d`, `1m` or `1y`.
    #[serde(
        rename = "secrets.stackable.tech/backend.autotls.cert.restart-buffer",
        default = "default_cert_restart_buffer"
    )]
    pub autotls_cert_restart_buffer: Duration,
}

fn default_cert_restart_buffer() -> Duration {
    DEFAULT_CERT_RESTART_BUFFER
}

fn default_cert_lifetime() -> Duration {
    DEFAULT_CERT_LIFETIME
}

impl SecretVolumeSelector {
    /// Returns all addresses associated with a certain [`SecretScope`]
    fn scope_addresses<'a>(
        &'a self,
        pod_info: &'a pod_info::PodInfo,
        scope: &scope::SecretScope,
    ) -> Vec<Address> {
        match scope {
            scope::SecretScope::Node => {
                let mut addrs = vec![Address::Dns(pod_info.node_name.clone())];
                addrs.extend(pod_info.node_ips.iter().copied().map(Address::Ip));
                addrs
            }
            scope::SecretScope::Pod => {
                let mut addrs = Vec::new();
                if let Some(svc_name) = &pod_info.service_name {
                    addrs.push(Address::Dns(format!(
                        "{}.{}.svc.cluster.local",
                        svc_name, self.namespace
                    )));
                    addrs.push(Address::Dns(format!(
                        "{}.{}.{}.svc.cluster.local",
                        self.pod, svc_name, self.namespace
                    )));
                }
                addrs.extend(pod_info.pod_ips.iter().copied().map(Address::Ip));
                addrs
            }
            scope::SecretScope::Service { name } => vec![Address::Dns(format!(
                "{}.{}.svc.cluster.local",
                name, self.namespace
            ))],
        }
    }

    fn default_kerberos_service_names() -> Vec<String> {
        vec!["HTTP".to_string()]
    }

    fn deserialize_some<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
        de: D,
    ) -> Result<Option<T>, D::Error> {
        T::deserialize(de).map(Some)
    }

    fn deserialize_str_vec<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<String>, D::Error> {
        let full_str = String::deserialize(de)?;
        Ok(full_str.split(',').map(str::to_string).collect())
    }
}

#[derive(Debug)]
pub struct SecretContents {
    pub data: SecretData,
    pub expires_after: Option<DateTime<FixedOffset>>,
}

impl SecretContents {
    fn new(data: SecretData) -> Self {
        Self {
            data,
            expires_after: None,
        }
    }

    fn expires_after(mut self, deadline: DateTime<FixedOffset>) -> Self {
        self.expires_after = Some(deadline);
        self
    }
}

/// This trait needs to be implemented by all secret providers.
/// It gets the pod information as well as volume definition and has to
/// return any number of files.
#[async_trait]
pub trait SecretBackend: Send + Sync {
    type Error: SecretBackendError;

    /// Provision or load secret data from the source.
    async fn get_secret_data(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: pod_info::PodInfo,
    ) -> Result<SecretContents, Self::Error>;

    /// Try to predict which nodes would be able to provision this secret.
    ///
    /// Should return `None` if no constraints apply, `Some(HashSet::new())` is interpreted as "no nodes match the given constraints".
    ///
    /// The default stub implementation assumes that no constraints apply.
    async fn get_qualified_node_names(
        &self,
        selector: &SecretVolumeSelector,
    ) -> Result<Option<HashSet<String>>, Self::Error> {
        // selector is unused in the stub implementation, but should still be used in all "real" impls
        let _ = selector;
        Ok(None)
    }
}

pub trait SecretBackendError: std::error::Error + Send + Sync + 'static {
    fn grpc_code(&self) -> tonic::Code;
}

impl SecretBackendError for Infallible {
    fn grpc_code(&self) -> tonic::Code {
        match *self {}
    }
}
