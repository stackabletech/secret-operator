//! Collects or generates secret data based on the request in the Kubernetes `Volume` definition

pub mod cert_manager;
pub mod dynamic;
pub mod k8s_search;
pub mod kerberos_keytab;
pub mod pod_info;
pub mod scope;
pub mod tls;

use std::{collections::HashSet, convert::Infallible, fmt::Debug};

use async_trait::async_trait;
pub use cert_manager::CertManager;
pub use k8s_search::K8sSearch;
pub use kerberos_keytab::KerberosKeytab;
use kube_runtime::reflector::ObjectRef;
use pod_info::Address;
use scope::SecretScope;
use serde::{Deserialize, Deserializer, Serialize, de::Unexpected};
use snafu::{OptionExt, Snafu};
use stackable_operator::{
    crd::listener,
    k8s_openapi::chrono::{DateTime, FixedOffset},
    kube::api::DynamicObject,
    shared::time::Duration,
};
pub use tls::TlsGenerate;

use self::pod_info::SchedulingPodInfo;
#[cfg(doc)]
use crate::crd::TrustStore;
use crate::format::{
    SecretData, SecretFormat,
    well_known::{CompatibilityOptions, NamingOptions},
};

/// Configuration provided by the `Volume` selecting what secret data should be provided
///
/// Fields beginning with `csi.storage.k8s.io/` are provided by the Kubelet
#[derive(Deserialize, Debug)]
pub struct SecretVolumeSelector {
    #[serde(flatten)]
    pub internal: InternalSecretVolumeSelectorParams,

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
    ///
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

    /// Compatibility options used by (legacy) applications.
    #[serde(flatten)]
    pub compat: CompatibilityOptions,

    /// The (custom) filenames used by secrets.
    #[serde(flatten)]
    pub names: NamingOptions,

    /// The TLS cert lifetime (when using the [`tls`] backend).
    /// The format is documented in <https://docs.stackable.tech/home/nightly/concepts/duration>.
    #[serde(
        rename = "secrets.stackable.tech/backend.autotls.cert.lifetime",
        default = "default_cert_lifetime"
    )]
    pub autotls_cert_lifetime: Duration,

    /// The amount of time the Pod using the cert gets restarted before the cert expires.
    /// Keep in mind that there can be multiple Pods - such as 80 datanodes - trying to
    /// shut down at the same time. It can take some hours until all Pods are restarted
    /// in a rolling fashion.
    /// The format is documented in <https://docs.stackable.tech/home/nightly/concepts/duration>.
    #[serde(
        rename = "secrets.stackable.tech/backend.autotls.cert.restart-buffer",
        default = "default_cert_restart_buffer"
    )]
    pub autotls_cert_restart_buffer: Duration,

    /// The part of the certificate's lifetime that may be removed for jittering.
    /// Must be within 0.0 and 1.0.
    #[serde(
        rename = "secrets.stackable.tech/backend.autotls.cert.jitter-factor",
        deserialize_with = "SecretVolumeSelector::deserialize_str_as_f64",
        default = "default_cert_jitter_factor"
    )]
    pub autotls_cert_jitter_factor: f64,

    /// The TLS cert lifetime (when using the [`cert_manager`] backend).
    ///
    /// The format is documented in <https://docs.stackable.tech/home/nightly/concepts/duration>.
    #[serde(
        rename = "secrets.stackable.tech/backend.cert-manager.cert.lifetime",
        deserialize_with = "SecretVolumeSelector::deserialize_some",
        default
    )]
    pub cert_manager_cert_lifetime: Option<Duration>,

    // TODO (@Techassi): Name to be decided. Will potentially be renamed.
    /// Only provision non-sensitive secret data.
    ///
    /// - TLS (PEM): Only provision the `ca.crt` file
    /// - TLS (PKCS#12): Only provision the `truststore.p12` file
    /// - Kerberos: Only provision the `krb5.conf` file
    ///
    /// This defaults to `false` to be backwords compatible with behaviour before SDP 26.3.0.
    #[serde(
        rename = "secrets.stackable.tech/only-provision-identity",
        deserialize_with = "SecretVolumeSelector::deserialize_str_as_bool",
        default
    )]
    pub only_provision_identity: bool,
}

/// Configuration provided by the [`TrustStore`] selecting what trust data should be provided.
pub struct TrustSelector {
    /// The name of the [`TrustStore`]'s `Namespace`.
    pub namespace: String,
}

/// Internal parameters of [`SecretVolumeSelector`] managed by secret-operator itself.
// These are optional even if they are set unconditionally, because otherwise we will
// fail to restore volumes (after Node reboots etc) from before they were added during upgrades.
//
// They are also not set when using CSI Ephemeral volumes (see https://github.com/stackabletech/secret-operator/issues/481),
// because this bypasses the CSI Controller entirely.
#[derive(Deserialize, Serialize, Debug)]
pub struct InternalSecretVolumeSelectorParams {
    /// The name of the PersistentVolumeClaim that owns this volume
    #[serde(
        rename = "secrets.stackable.tech/internal.pvc.name",
        deserialize_with = "SecretVolumeSelector::deserialize_some",
        default
    )]
    pub pvc_name: Option<String>,
}

fn default_cert_restart_buffer() -> Duration {
    tls::DEFAULT_CERT_RESTART_BUFFER
}

fn default_cert_lifetime() -> Duration {
    tls::DEFAULT_CERT_LIFETIME
}

fn default_cert_jitter_factor() -> f64 {
    tls::DEFAULT_CERT_JITTER_FACTOR
}

#[derive(Snafu, Debug)]
#[snafu(module)]
pub enum ScopeAddressesError {
    #[snafu(display(
        "listener addresses were not fetched (this is likely a bug in secret-operator)"
    ))]
    ListenerAddressesNotFetched,

    #[snafu(display("no addresses found for listener {listener} on {pod_listeners}"))]
    NoListenerAddresses {
        listener: String,
        pod_listeners: ObjectRef<listener::v1alpha1::PodListeners>,
    },
}

impl ScopeAddressesError {
    pub fn secondary_object(&self) -> Option<ObjectRef<DynamicObject>> {
        match self {
            Self::ListenerAddressesNotFetched => None,
            Self::NoListenerAddresses { pod_listeners, .. } => Some(pod_listeners.clone().erase()),
        }
    }
}

impl SecretVolumeSelector {
    /// Returns all addresses associated with a certain [`SecretScope`]
    fn scope_addresses<'a>(
        &'a self,
        pod_info: &'a pod_info::PodInfo,
        scope: &scope::SecretScope,
    ) -> Result<Vec<Address>, ScopeAddressesError> {
        use scope_addresses_error::*;
        let cluster_domain = &pod_info.kubernetes_cluster_domain;
        let namespace = &self.namespace;
        Ok(match scope {
            scope::SecretScope::Node => {
                let mut addrs = vec![Address::Dns(pod_info.node_name.clone())];
                addrs.extend(pod_info.node_ips.iter().copied().map(Address::Ip));
                addrs
            }
            scope::SecretScope::Pod => {
                let mut addrs = Vec::new();
                if let Some(svc_name) = &pod_info.service_name {
                    addrs.push(Address::Dns(format!(
                        "{svc_name}.{namespace}.svc.{cluster_domain}"
                    )));
                    addrs.push(Address::Dns(format!(
                        "{pod}.{svc_name}.{namespace}.svc.{cluster_domain}",
                        pod = self.pod
                    )));
                }
                addrs.extend(pod_info.pod_ips.iter().copied().map(Address::Ip));
                addrs
            }
            scope::SecretScope::Service { name } => vec![Address::Dns(format!(
                "{name}.{namespace}.svc.{cluster_domain}",
            ))],
            scope::SecretScope::ListenerVolume { name } => match &pod_info.listener_addresses {
                Some(listener_addresses) => listener_addresses
                    .by_listener_volume_name
                    .get(name)
                    .with_context(|| NoListenerAddressesSnafu {
                        listener: name,
                        pod_listeners: listener_addresses.source.clone(),
                    })?
                    .to_vec(),
                None => return ListenerAddressesNotFetchedSnafu.fail(),
            },
        })
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

    fn deserialize_str_as_f64<'de, D: Deserializer<'de>>(de: D) -> Result<f64, D::Error> {
        let str = String::deserialize(de)?;
        str.parse().map_err(|_| {
            <D::Error as serde::de::Error>::invalid_value(
                Unexpected::Str(&str),
                &"a string containing a f64",
            )
        })
    }

    fn deserialize_str_as_bool<'de, D: Deserializer<'de>>(de: D) -> Result<bool, D::Error> {
        let str = String::deserialize(de)?;
        str.parse().map_err(|_| {
            <D::Error as serde::de::Error>::invalid_value(
                Unexpected::Str(&str),
                &"a string containing a boolean",
            )
        })
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
pub trait SecretBackend: Debug + Send + Sync {
    type Error: SecretBackendError;

    /// Provision or load secret data from the source.
    async fn get_secret_data(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: pod_info::PodInfo,
    ) -> Result<SecretContents, Self::Error>;

    async fn get_trust_data(&self, selector: &TrustSelector)
    -> Result<SecretContents, Self::Error>;

    /// Try to predict which nodes would be able to provision this secret.
    ///
    /// Should return `None` if no constraints apply, `Some(HashSet::new())` is interpreted as "no nodes match the given constraints".
    ///
    /// The default stub implementation assumes that no constraints apply.
    async fn get_qualified_node_names(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: SchedulingPodInfo,
    ) -> Result<Option<HashSet<String>>, Self::Error> {
        // selector and pod_info are unused in the stub implementation, but should still be used in "real" impls
        let _ = (selector, pod_info);
        Ok(None)
    }
}

pub trait SecretBackendError: std::error::Error + Send + Sync + 'static {
    fn grpc_code(&self) -> tonic::Code;
    fn secondary_object(&self) -> Option<ObjectRef<DynamicObject>>;
}

impl SecretBackendError for Infallible {
    fn grpc_code(&self) -> tonic::Code {
        match *self {}
    }

    fn secondary_object(&self) -> Option<ObjectRef<DynamicObject>> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde::de::{IntoDeserializer, value::MapDeserializer};

    use super::*;

    fn required_fields_map() -> HashMap<String, String> {
        HashMap::from([
            (
                "secrets.stackable.tech/class".to_owned(),
                "my-class".to_owned(),
            ),
            (
                "csi.storage.k8s.io/pod.name".to_owned(),
                "my-pod".to_owned(),
            ),
            (
                "csi.storage.k8s.io/pod.namespace".to_owned(),
                "my-namespace".to_owned(),
            ),
        ])
    }

    #[test]
    fn deserialize_selector() {
        let map = required_fields_map();

        let _ =
            SecretVolumeSelector::deserialize::<MapDeserializer<'_, _, serde::de::value::Error>>(
                map.into_deserializer(),
            )
            .unwrap();
    }

    #[test]
    fn deserialize_selector_compat() {
        let mut map = required_fields_map();
        map.insert(
            "secrets.stackable.tech/format.compatibility.tls-pkcs12.password".to_owned(),
            "supersecret".to_owned(),
        );

        let _ =
            SecretVolumeSelector::deserialize::<MapDeserializer<'_, _, serde::de::value::Error>>(
                map.into_deserializer(),
            )
            .unwrap();
    }
}
