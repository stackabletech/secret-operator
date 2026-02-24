//! See [`PodInfo`]

use std::{
    collections::{BTreeMap, HashMap},
    net::{AddrParseError, IpAddr},
};

use futures::{StreamExt, TryStreamExt};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::networking::DomainName,
    crd::listener,
    k8s_openapi::api::core::v1::{Node, PersistentVolumeClaim, Pod},
    kube::runtime::reflector::{Lookup, ObjectRef},
};

use super::scope::SecretScope;
use crate::utils::trystream_any;

const LISTENER_PVC_ANNOTATION_LISTENER_NAME: &str = "listeners.stackable.tech/listener-name";
const LISTENER_PVC_ANNOTATION_LISTENER_CLASS: &str = "listeners.stackable.tech/listener-class";

#[derive(Debug, Snafu)]
#[snafu(module)]
#[allow(clippy::large_enum_variant)]
pub enum FromPodError {
    #[snafu(display("failed to parse address {address:?}"))]
    IllegalAddress {
        source: std::net::AddrParseError,
        address: String,
    },

    #[snafu(display("pod has not yet been scheduled to a node"))]
    NoNode,

    #[snafu(display("pod has no namespace"))]
    NoNamespace,

    #[snafu(display("pod has no name"))]
    NoPodName,

    #[snafu(display("pod has no uid"))]
    NoPodUid,

    #[snafu(display("failed to get {node}"))]
    GetNode {
        source: stackable_operator::client::Error,
        node: ObjectRef<Node>,
    },

    #[snafu(display("pod has no listener volume {listener_volume}"))]
    GetListenerVolume { listener_volume: String },

    #[snafu(display("failed to get listener PVC {listener_pvc} for volume {listener_volume}"))]
    GetListenerPvc {
        source: stackable_operator::client::Error,
        listener_volume: String,
        listener_pvc: ObjectRef<PersistentVolumeClaim>,
    },

    #[snafu(display("failed to get {listener} for volume {listener_volume}"))]
    GetListener {
        source: stackable_operator::client::Error,
        listener_volume: String,
        listener: ObjectRef<listener::v1alpha1::Listener>,
    },

    #[snafu(display("failed to get {listener_class} for volume {listener_volume}"))]
    GetListenerClass {
        source: stackable_operator::client::Error,
        listener_volume: String,
        listener_class: ObjectRef<listener::v1alpha1::ListenerClass>,
    },

    #[snafu(display("{listener} has no class for volume {listener_volume}"))]
    ListenerHasNoClass {
        listener_volume: String,
        listener: ObjectRef<listener::v1alpha1::Listener>,
    },

    #[snafu(display(
        "{listener_pvc} has no listener or listener class for volume {listener_volume}"
    ))]
    UnresolvableListenerPvc {
        listener_volume: String,
        listener_pvc: ObjectRef<PersistentVolumeClaim>,
    },

    #[snafu(display("failed to get {pod_listeners} for {pod}"))]
    GetPodListeners {
        source: stackable_operator::client::Error,
        pod_listeners: ObjectRef<listener::v1alpha1::PodListeners>,
        pod: ObjectRef<Pod>,
    },

    #[snafu(display("{pod_listeners} has no addresses for listener {listener} yet"))]
    NoPodListenerAddresses {
        pod_listeners: ObjectRef<listener::v1alpha1::PodListeners>,
        listener: String,
    },
}

/// Validated metadata about a scheduled [`Pod`]
#[derive(Debug)]
pub struct PodInfo {
    pub pod_ips: Vec<IpAddr>,
    pub service_name: Option<String>,
    pub node_name: String,
    pub node_ips: Vec<IpAddr>,
    pub listener_addresses: Option<ListenerAddresses>,
    pub kubernetes_cluster_domain: DomainName,
    pub scheduling: SchedulingPodInfo,
}

impl PodInfo {
    pub async fn from_pod(
        client: &stackable_operator::client::Client,
        pod: Pod,
        scopes: &[SecretScope],
    ) -> Result<Self, FromPodError> {
        use from_pod_error::*;
        let node_name = pod
            .spec
            .as_ref()
            .and_then(|spec| spec.node_name.clone())
            .context(NoNodeSnafu)?;
        let node = client
            .get::<Node>(&node_name, &())
            .await
            .with_context(|_| GetNodeSnafu {
                node: ObjectRef::new(&node_name),
            })?;
        let scheduling = SchedulingPodInfo::from_pod(client, &pod, scopes).await?;
        let listener_addresses = if !scheduling.volume_listener_names.is_empty() {
            Some(ListenerAddresses::fetch_for_pod(client, &pod, &scheduling, scopes).await?)
        } else {
            // We don't care about the listener addresses if there is no listener scope, so we can save the API call
            None
        };
        Ok(Self {
            // This will generally be empty, since Kubernetes assigns pod IPs *after* CSI plugins are successful
            pod_ips: pod
                .status
                .iter()
                .flat_map(|status| &status.pod_ips)
                .flatten()
                .map(|ip| &ip.ip)
                .map(|ip| {
                    ip.parse()
                        .context(from_pod_error::IllegalAddressSnafu { address: ip })
                })
                .collect::<Result<_, _>>()?,
            service_name: pod.spec.as_ref().and_then(|spec| spec.subdomain.clone()),
            node_name,
            node_ips: node
                .status
                .iter()
                .flat_map(|status| status.addresses.as_deref())
                .flatten()
                .filter(|addr| addr.type_ == "ExternalIP" || addr.type_ == "InternalIP")
                .map(|ip| {
                    ip.address
                        .parse()
                        .context(from_pod_error::IllegalAddressSnafu {
                            address: &ip.address,
                        })
                })
                .collect::<Result<_, _>>()?,
            listener_addresses,
            kubernetes_cluster_domain: client.kubernetes_cluster_info.cluster_domain.clone(),
            scheduling,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Address {
    Dns(String),
    Ip(IpAddr),
}
impl TryFrom<(listener::v1alpha1::AddressType, &str)> for Address {
    type Error = AddrParseError;

    fn try_from(
        (ty, address): (listener::v1alpha1::AddressType, &str),
    ) -> Result<Self, Self::Error> {
        Ok(match ty {
            listener::v1alpha1::AddressType::Hostname => Address::Dns(address.to_string()),
            listener::v1alpha1::AddressType::Ip => Address::Ip(address.parse()?),
        })
    }
}

/// Validated metadata about a pod that may or may not be scheduled yet.
#[derive(Debug)]
pub struct SchedulingPodInfo {
    pub namespace: String,

    /// Map from volume names to Listener names.
    pub volume_listener_names: HashMap<String, String>,

    /// Whether the secret has a node or _node-equivalent_ scope.
    ///
    /// An example of a node-equivalent scope is a listener scope that refers to a node-scoped listener.
    pub has_node_scope: bool,
}

impl SchedulingPodInfo {
    pub async fn from_pod(
        client: &stackable_operator::client::Client,
        pod: &Pod,
        scopes: &[SecretScope],
    ) -> Result<Self, FromPodError> {
        use from_pod_error::*;
        let pod_name = pod.metadata.name.clone().context(NoPodNameSnafu)?;
        let namespace = pod.metadata.namespace.clone().context(NoNamespaceSnafu)?;
        let volume_pvc_names = pod
            .spec
            .iter()
            .flat_map(|ps| &ps.volumes)
            .flatten()
            .filter_map(|vol| {
                Some((
                    vol.name.clone(),
                    if vol.ephemeral.is_some() {
                        format!("{}-{}", pod_name, vol.name)
                    } else {
                        vol.persistent_volume_claim.as_ref()?.claim_name.clone()
                    },
                ))
            })
            .collect::<HashMap<_, _>>();
        let volume_listener_pvcs = futures::stream::iter(scopes)
            .filter_map(|scope| async move {
                match scope {
                    SecretScope::ListenerVolume { name } => Some(name),
                    _ => None,
                }
            })
            .map(|listener_volume| {
                Ok((
                    listener_volume,
                    volume_pvc_names
                        .get(listener_volume)
                        .context(GetListenerVolumeSnafu { listener_volume })?,
                ))
            })
            .and_then(|(listener_volume, pvc_name)| {
                let namespace = &namespace;
                async move {
                    let pvc = client
                        .get::<PersistentVolumeClaim>(pvc_name, namespace)
                        .await
                        .context(GetListenerPvcSnafu {
                            listener_volume,
                            listener_pvc: ObjectRef::<PersistentVolumeClaim>::new(pvc_name)
                                .within(namespace),
                        })?;
                    Ok((listener_volume, pvc_name, pvc))
                }
            })
            .try_collect::<Vec<_>>()
            .await?;
        let volume_listener_names = volume_listener_pvcs
            .iter()
            .map(|(listener_volume, pvc_name, pvc)| {
                let listener_name = pvc
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|ann| ann.get(LISTENER_PVC_ANNOTATION_LISTENER_NAME))
                    .unwrap_or(pvc_name);
                (listener_volume.to_string(), listener_name.to_string())
            })
            .collect::<HashMap<_, _>>();
        let has_node_scope = scopes.contains(&SecretScope::Node)
            || trystream_any(futures::stream::iter(volume_listener_pvcs).then(
                |(listener_volume, _, pvc)| {
                    listener_pvc_is_node_scoped(client, &namespace, listener_volume, pvc)
                },
            ))
            .await?;
        Ok(SchedulingPodInfo {
            volume_listener_names,
            has_node_scope,
            namespace,
        })
    }
}

async fn listener_pvc_is_node_scoped(
    client: &stackable_operator::client::Client,
    namespace: &str,
    listener_volume: &str,
    pvc: PersistentVolumeClaim,
) -> Result<bool, FromPodError> {
    use from_pod_error::*;
    let empty = BTreeMap::new();
    let pvc_annotations = pvc.metadata.annotations.as_ref().unwrap_or(&empty);
    let listener: listener::v1alpha1::Listener;
    let listener_class_name = if let Some(cn) =
        pvc_annotations.get(LISTENER_PVC_ANNOTATION_LISTENER_CLASS)
    {
        cn
    } else if let Some(listener_name) = pvc_annotations.get(LISTENER_PVC_ANNOTATION_LISTENER_NAME) {
        listener = client
            .get::<listener::v1alpha1::Listener>(listener_name, namespace)
            .await
            .context(GetListenerSnafu {
                listener_volume,
                listener: ObjectRef::<listener::v1alpha1::Listener>::new(listener_name)
                    .within(namespace),
            })?;
        listener
            .spec
            .class_name
            .as_deref()
            .context(ListenerHasNoClassSnafu {
                listener_volume,
                listener: ObjectRef::from_obj(&listener),
            })?
    } else {
        return UnresolvableListenerPvcSnafu {
            listener_volume,
            listener_pvc: ObjectRef::from_obj(&pvc),
        }
        .fail();
    };
    let listener_class = client
        .get::<listener::v1alpha1::ListenerClass>(listener_class_name, &())
        .await
        .context(GetListenerClassSnafu {
            listener_volume,
            listener_class: ObjectRef::<listener::v1alpha1::ListenerClass>::new(
                listener_class_name,
            ),
        })?;
    Ok(listener_class.spec.service_type == listener::v1alpha1::ServiceType::NodePort)
}

#[derive(Debug)]
pub struct ListenerAddresses {
    pub source: ObjectRef<listener::v1alpha1::PodListeners>,
    pub by_listener_volume_name: HashMap<String, Vec<Address>>,
}

impl ListenerAddresses {
    async fn fetch_for_pod(
        client: &stackable_operator::client::Client,
        pod: &Pod,
        pod_info: &SchedulingPodInfo,
        scopes: &[SecretScope],
    ) -> Result<ListenerAddresses, FromPodError> {
        use from_pod_error::*;
        let pod_listeners_name = format!(
            "pod-{}",
            pod.metadata.uid.as_deref().context(NoPodUidSnafu)?
        );
        let pod_listeners = client
            .get::<listener::v1alpha1::PodListeners>(&pod_listeners_name, &pod_info.namespace)
            .await
            .context(GetPodListenersSnafu {
                pod_listeners: ObjectRef::<listener::v1alpha1::PodListeners>::new(
                    &pod_listeners_name,
                )
                .within(&pod_info.namespace),
                pod: ObjectRef::from_obj(pod),
            })?;
        let listeners_ref = ObjectRef::from_obj(&pod_listeners);
        Ok(ListenerAddresses {
            source: pod_listeners.to_object_ref(()),
            by_listener_volume_name: scopes
                .iter()
                .filter_map(|scope| match scope {
                    SecretScope::ListenerVolume { name } => Some(name),
                    _ => None,
                })
                .map(|listener| {
                    let addresses = pod_listeners
                        .spec
                        .listeners
                        .get(listener)
                        .and_then(|ingresses| ingresses.ingress_addresses.as_ref())
                        .context(NoPodListenerAddressesSnafu {
                            pod_listeners: listeners_ref.clone(),
                            listener,
                        })?;
                    Ok((
                        listener.clone(),
                        addresses
                            .iter()
                            .map(|ingr| {
                                (ingr.address_type, &*ingr.address).try_into().context(
                                    IllegalAddressSnafu {
                                        address: &ingr.address,
                                    },
                                )
                            })
                            .collect::<Result<Vec<_>, FromPodError>>()?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, FromPodError>>()?,
        })
    }
}
