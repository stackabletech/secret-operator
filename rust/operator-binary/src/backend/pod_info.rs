//! See [`PodInfo`]

use std::{collections::HashMap, net::IpAddr};

use csi_grpc::listop::v1::listener_node_client::ListenerNodeClient;
use futures::{FutureExt, StreamExt};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    commons::listener::PodListeners,
    k8s_openapi::api::core::v1::{Node, Pod},
    kube::runtime::reflector::ObjectRef,
};
use tonic::{body::BoxBody, client::GrpcService, transport::Channel};

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
    pub listener_addresses: HashMap<String, Vec<String>>,
}

impl PodInfo {
    pub async fn from_pod(
        client: &stackable_operator::client::Client,
        listop_client: &mut ListenerNodeClient<Channel>,
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
                            .into_iter()
                            .map(|ingr| ingr.address)
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<HashMap<_, _>>(),
        })
    }
}

#[derive(Debug)]
pub enum Address {
    Dns(String),
    Ip(IpAddr),
}
