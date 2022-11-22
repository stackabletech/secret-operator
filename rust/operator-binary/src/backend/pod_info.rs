//! See [`PodInfo`]

use std::net::IpAddr;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::api::core::v1::{Node, Pod},
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
        })
    }
}

#[derive(Debug)]
pub enum Address {
    Dns(String),
    Ip(IpAddr),
}
