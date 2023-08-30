//! See [`PodInfo`]

use std::{collections::HashMap, net::IpAddr};

use futures::StreamExt;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::listener::{AddressType, PodListeners},
    k8s_openapi::api::core::v1::{Node, PersistentVolumeClaim, Pod},
    kube::runtime::reflector::ObjectRef,
};

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
    #[snafu(display("failed to get {node}"))]
    GetNode {
        source: stackable_operator::error::Error,
        node: ObjectRef<Node>,
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
    ) -> Result<Self, FromPodError> {
        let node_name = pod
            .spec
            .as_ref()
            .and_then(|spec| spec.node_name.clone())
            .context(from_pod_error::NoNodeSnafu)?;
        let node = client
            .get::<Node>(&node_name, &())
            .await
            .with_context(|_| from_pod_error::GetNodeSnafu {
                node: ObjectRef::new(&node_name),
            })?;
        let listeners = client
            .get::<PodListeners>(
                &format!("pod-{}", pod.metadata.uid.as_deref().unwrap()),
                pod.metadata.namespace.as_deref().unwrap(),
            )
            .await
            .unwrap();
        let scheduling = SchedulingPodInfo::from_pod(client, &pod).await;
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
            listener_addresses: listeners
                .spec
                .listeners
                .into_iter()
                .map(|(listener, ingresses)| {
                    (
                        listener,
                        ingresses
                            .ingress_addresses
                            .unwrap()
                            .into_iter()
                            .map(|ingr| match ingr.address_type {
                                AddressType::Hostname => Address::Dns(ingr.address),
                                AddressType::Ip => Address::Ip(ingr.address.parse().unwrap()),
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<HashMap<_, _>>(),
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
    pub volume_pvcs: HashMap<String, String>,
    pub volume_listeners: HashMap<String, String>,
}

impl SchedulingPodInfo {
    pub async fn from_pod(client: &stackable_operator::client::Client, pod: &Pod) -> Self {
        let volume_pvcs = pod
            .spec
            .iter()
            .flat_map(|ps| &ps.volumes)
            .flatten()
            .filter_map(|vol| {
                Some((
                    vol.name.clone(),
                    if vol.ephemeral.is_some() {
                        format!("{}-{}", pod.metadata.name.as_deref().unwrap(), vol.name)
                    } else {
                        vol.persistent_volume_claim.as_ref()?.claim_name.clone()
                    },
                ))
            })
            .collect::<HashMap<_, _>>();
        let volume_listeners = futures::stream::iter(&volume_pvcs)
            .then(|(volume, pvc_name)| async move {
                let pvc = client
                    .get::<PersistentVolumeClaim>(
                        pvc_name,
                        pod.metadata.namespace.as_deref().unwrap(),
                    )
                    .await
                    .unwrap();
                let listener_name = pvc
                    .metadata
                    .annotations
                    .and_then(|mut ann| ann.remove("listeners.stackable.tech/listener-name"))
                    .unwrap_or(pvc_name.to_string());
                (volume.to_string(), listener_name)
            })
            .collect::<HashMap<_, _>>()
            .await;
        SchedulingPodInfo {
            volume_pvcs,
            volume_listeners,
        }
    }
}
