use std::net::IpAddr;

use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::k8s_openapi::api::core::v1::Pod;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromPodError {
    #[snafu(display("failed to parse IP address {ip:?}"))]
    IllegalIp {
        source: std::net::AddrParseError,
        ip: String,
    },
    #[snafu(display("pod has not yet been scheduled to a node"))]
    NoNode,
}

pub struct PodInfo {
    pub pod_ips: Vec<IpAddr>,
    pub service_name: Option<String>,
    pub node_name: String,
    pub node_ips: Vec<IpAddr>,
}

impl TryFrom<Pod> for PodInfo {
    type Error = FromPodError;

    fn try_from(pod: Pod) -> Result<Self, Self::Error> {
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
            node_name: pod
                .spec
                .and_then(|spec| spec.node_name)
                .context(from_pod_error::NoNodeSnafu)?,
            node_ips: pod
                .status
                .iter()
                .flat_map(|status| status.host_ip.as_deref())
                .map(|ip| ip.parse().context(from_pod_error::IllegalIpSnafu { ip }))
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Debug)]
pub enum Address {
    Dns(String),
    Ip(IpAddr),
}
