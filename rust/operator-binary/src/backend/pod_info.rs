//! See [`PodInfo`]

use std::{collections::HashMap, net::IpAddr};

use csi_grpc::listop::v1::listener_node_client::ListenerNodeClient;
use futures::{FutureExt, StreamExt};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
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
        let listener_volume_names = ["listener"];
        // let listener_volume_names = pod
        //     .spec
        //     .iter()
        //     .flat_map(|spec| &spec.volumes)
        //     .flatten()
        //     // .flat_map(|volume| volume.ephemeral.as_ref()?.volume_claim_template.as_ref())
        //     .filter(|volume| {
        //         dbg!(volume);
        //         volume.ephemeral.as_ref().and_then(|v| {
        //             v.volume_claim_template
        //                 .as_ref()?
        //                 .spec
        //                 .storage_class_name
        //                 .as_deref()
        //         }) == Some("listeners.stackable.tech")
        //     })
        //     .map(|volume| &volume.name)
        //     .collect::<Vec<_>>();
        let mut listener_addresses = HashMap::new();
        for listener_name in listener_volume_names {
            listener_addresses.insert(
                listener_name.to_string(),
                listop_client
                    .get_local_listener_addresses_for_pod(
                        csi_grpc::listop::v1::GetLocalListenerAddressesForPodRequest {
                            namespace: pod.metadata.namespace.clone().unwrap(),
                            pod: pod.metadata.name.clone().unwrap(),
                            listener: listener_name.to_string(),
                        },
                    )
                    .await
                    .unwrap()
                    .into_inner()
                    .ingresses
                    .into_iter()
                    .map(|ingress| ingress.address)
                    .collect::<Vec<_>>(),
            );
        }
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
        })
    }
}

#[derive(Debug)]
pub enum Address {
    Dns(String),
    Ip(IpAddr),
}
