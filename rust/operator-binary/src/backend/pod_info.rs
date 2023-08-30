//! See [`PodInfo`]

use std::{collections::HashMap, net::IpAddr};

use futures::{StreamExt, TryStreamExt};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::listener::{AddressType, PodListeners},
    k8s_openapi::api::core::v1::{Node, PersistentVolumeClaim, Pod},
    kube::runtime::reflector::ObjectRef,
};

use super::scope::SecretScope;

#[derive(Debug, Snafu)]
#[snafu(module)]
#[allow(clippy::large_enum_variant)]
pub enum FromPodError {
    #[snafu(display("failed to parse IP address {ip:?}"))]
    IllegalIp {
        source: std::net::AddrParseError,
        ip: String,
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
        source: stackable_operator::error::Error,
        node: ObjectRef<Node>,
    },
    #[snafu(display("pod has no listener volume {listener_volume}"))]
    GetListenerVolume { listener_volume: String },
    #[snafu(display("fialed to get listener PVC {listener_pvc} for volume {listener_volume}"))]
    GetListenerPvc {
        source: stackable_operator::error::Error,
        listener_volume: String,
        listener_pvc: ObjectRef<PersistentVolumeClaim>,
    },
    #[snafu(display("failed to get {pod_listeners} for {pod}"))]
    GetPodListeners {
        source: stackable_operator::error::Error,
        pod_listeners: ObjectRef<PodListeners>,
        pod: ObjectRef<Pod>,
    },
    #[snafu(display("{pod_listeners} has no addresses for listener {listener} yet"))]
    NoPodListenerAddresses {
        pod_listeners: ObjectRef<PodListeners>,
        listener: String,
    },
}

/// Validated metadata about a scheduled [`Pod`]
pub struct PodInfo {
    pub pod_ips: Vec<IpAddr>,
    pub service_name: Option<String>,
    pub node_name: String,
    pub node_ips: Vec<IpAddr>,
    pub listener_addresses: HashMap<String, Vec<Address>>,
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
        let listener_addresses = if !scheduling.volume_listeners.is_empty() {
            let pod_listeners_name = format!(
                "pod-{}",
                pod.metadata.uid.as_deref().context(NoPodUidSnafu)?
            );
            let listeners = client
                .get::<PodListeners>(&pod_listeners_name, &scheduling.namespace)
                .await
                .context(GetPodListenersSnafu {
                    pod_listeners: ObjectRef::<PodListeners>::new(&pod_listeners_name)
                        .within(&scheduling.namespace),
                    pod: ObjectRef::from_obj(&pod),
                })?;
            let listeners_ref = ObjectRef::from_obj(&listeners);
            listeners
                .spec
                .listeners
                .into_iter()
                .map(|(listener, ingresses)| {
                    let addresses =
                        ingresses
                            .ingress_addresses
                            .context(NoPodListenerAddressesSnafu {
                                pod_listeners: listeners_ref.clone(),
                                listener: &listener,
                            })?;
                    Ok((
                        listener,
                        addresses
                            .into_iter()
                            .map(|ingr| {
                                Ok(match ingr.address_type {
                                    AddressType::Hostname => Address::Dns(ingr.address),
                                    AddressType::Ip => Address::Ip(
                                        ingr.address
                                            .parse()
                                            .context(IllegalIpSnafu { ip: ingr.address })?,
                                    ),
                                })
                            })
                            .collect::<Result<Vec<_>, FromPodError>>()?,
                    ))
                })
                .collect::<Result<HashMap<_, _>, FromPodError>>()?
        } else {
            HashMap::new()
        };
        Ok(Self {
            // This will generally be empty, since Kubernetes assigns pod IPs *after* CSI plugins are successful
            pod_ips: pod
                .status
                .iter()
                .flat_map(|status| &status.pod_ips)
                .flatten()
                .flat_map(|ip| ip.ip.as_deref())
                .map(|ip| ip.parse().context(from_pod_error::IllegalIpSnafu { ip }))
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
                        .context(from_pod_error::IllegalIpSnafu { ip: &ip.address })
                })
                .collect::<Result<_, _>>()?,
            listener_addresses,
            scheduling,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Address {
    Dns(String),
    Ip(IpAddr),
}

/// Validated metadata about a pod that may or may not be scheduled yet.
pub struct SchedulingPodInfo {
    pub namespace: String,
    pub pod_name: String,
    pub volume_pvcs: HashMap<String, String>,
    pub volume_listeners: HashMap<String, String>,
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
        let volume_pvcs = pod
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
        let volume_listeners = futures::stream::iter(scopes)
            .filter_map(|scope| async move {
                match scope {
                    SecretScope::Listener { name } => Some(name),
                    _ => None,
                }
            })
            .map(|listener_volume| {
                Ok((
                    listener_volume,
                    volume_pvcs
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
                    let listener_name = pvc
                        .metadata
                        .annotations
                        .and_then(|mut ann| ann.remove("listeners.stackable.tech/listener-name"))
                        .unwrap_or(pvc_name.to_string());
                    Ok((listener_volume.to_string(), listener_name))
                }
            })
            .try_collect::<HashMap<_, _>>()
            .await?;
        Ok(SchedulingPodInfo {
            volume_pvcs,
            volume_listeners,
            pod_name,
            namespace,
        })
    }
}
