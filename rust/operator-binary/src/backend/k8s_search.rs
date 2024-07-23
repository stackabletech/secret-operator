//! Queries the Kubernetes API for predefined [`Secret`] objects

use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::LabelSelector, ByteString,
    },
    kube::api::{ListParams, ObjectMeta},
    kvp::{LabelError, LabelSelectorExt, Labels},
};

use crate::{
    cert_manager,
    crd::{CertManagerIssuer, SearchNamespace},
    format::SecretData,
    utils::Unloggable,
};

use super::{
    pod_info::{Address, PodInfo, SchedulingPodInfo},
    scope::SecretScope,
    ScopeAddressesError, SecretBackend, SecretBackendError, SecretContents, SecretVolumeSelector,
};

const LABEL_CLASS: &str = "secrets.stackable.tech/class";
const LABEL_SCOPE_NODE: &str = "secrets.stackable.tech/node";
const LABEL_SCOPE_POD: &str = "secrets.stackable.tech/pod";
const LABEL_SCOPE_SERVICE: &str = "secrets.stackable.tech/service";
const LABEL_SCOPE_LISTENER: &str = "secrets.stackable.tech/listener";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to get addresses for scope {scope}"))]
    ScopeAddresses {
        source: ScopeAddressesError,
        scope: SecretScope,
    },

    #[snafu(display("failed to apply cert-manager Certificate for volume"))]
    ApplyCertManagerCertificate {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to build Secret selector"))]
    SecretSelector {
        source: stackable_operator::kvp::SelectorError,
    },

    #[snafu(display("failed to query for secrets"))]
    SecretQuery {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("no Secrets matched label selector {label_selector:?}"))]
    NoSecret { label_selector: String },

    #[snafu(display("failed to find Listener name for volume {listener_volume}"))]
    NoListener { listener_volume: String },

    #[snafu(display("failed to build label"))]
    BuildLabel { source: LabelError },
}

impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::ScopeAddresses { .. } => tonic::Code::Unavailable,
            Error::SecretSelector { .. } => tonic::Code::FailedPrecondition,
            Error::SecretQuery { .. } => tonic::Code::FailedPrecondition,
            Error::ApplyCertManagerCertificate { .. } => tonic::Code::Unavailable,
            Error::NoSecret { .. } => tonic::Code::FailedPrecondition,
            Error::NoListener { .. } => tonic::Code::FailedPrecondition,
            Error::BuildLabel { .. } => tonic::Code::FailedPrecondition,
        }
    }
}

#[derive(Debug)]
pub struct K8sSearch {
    // Not secret per se, but isn't Debug: https://github.com/stackabletech/secret-operator/issues/411
    pub client: Unloggable<stackable_operator::client::Client>,
    pub search_namespace: SearchNamespace,
    pub cert_manager_issuer: Option<CertManagerIssuer>,
}

impl K8sSearch {
    fn search_ns_for_pod<'a>(&'a self, selector: &'a SecretVolumeSelector) -> &'a str {
        match &self.search_namespace {
            SearchNamespace::Pod {} => &selector.namespace,
            SearchNamespace::Name(ns) => ns,
        }
    }
}

#[async_trait]
impl SecretBackend for K8sSearch {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<SecretContents, Self::Error> {
        let labels = build_selector_labels(selector, LabelSelectorPodInfo::Scheduled(&pod_info))?;
        if let Some(cert_manager_issuer) = &self.cert_manager_issuer {
            let cert_name = &selector.internal.pvc_name;
            let mut dns_names = Vec::new();
            let mut ip_addresses = Vec::new();
            for scope in &selector.scope {
                for address in selector
                    .scope_addresses(&pod_info, scope)
                    .context(ScopeAddressesSnafu { scope })?
                {
                    match address {
                        Address::Dns(name) => dns_names.push(name),
                        Address::Ip(addr) => ip_addresses.push(addr.to_string()),
                    }
                }
            }
            let cert = cert_manager::Certificate {
                metadata: ObjectMeta {
                    name: Some(cert_name.clone()),
                    namespace: Some(self.search_ns_for_pod(selector).to_string()),
                    ..Default::default()
                },
                spec: cert_manager::CertificateSpec {
                    secret_name: cert_name.clone(),
                    secret_template: cert_manager::SecretTemplate {
                        annotations: BTreeMap::new(),
                        labels: labels.clone().into(),
                    },
                    dns_names,
                    ip_addresses,
                    issuer_ref: cert_manager::IssuerRef {
                        name: cert_manager_issuer.name.clone(),
                        kind: cert_manager_issuer.kind,
                    },
                },
            };
            self.client
                .apply_patch("k8s-search-cert-manager", &cert, &cert)
                .await
                .context(ApplyCertManagerCertificateSnafu)?;
        }
        let label_selector = LabelSelector {
            match_expressions: None,
            match_labels: Some(labels.into()),
        }
        .to_query_string()
        .context(SecretSelectorSnafu)?;
        let secret = self
            .client
            .list::<Secret>(
                self.search_ns_for_pod(selector),
                &ListParams::default().labels(&label_selector),
            )
            .await
            .context(SecretQuerySnafu)?
            .into_iter()
            .next()
            .context(NoSecretSnafu { label_selector })?;
        Ok(SecretContents::new(SecretData::Unknown(
            secret
                .data
                .unwrap_or_default()
                .into_iter()
                .map(|(k, ByteString(v))| (k, v))
                .collect(),
        )))
    }

    async fn get_qualified_node_names(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: SchedulingPodInfo,
    ) -> Result<Option<HashSet<String>>, Self::Error> {
        if pod_info.has_node_scope
        // FIXME: how should node selection interact with cert manager?
            && self.cert_manager_issuer.is_none()
        {
            let labels =
                build_selector_labels(selector, LabelSelectorPodInfo::Scheduling(&pod_info))?;
            let label_selector = LabelSelector {
                match_expressions: None,
                match_labels: Some(labels.into()),
            }
            .to_query_string()
            .context(SecretSelectorSnafu)?;
            Ok(Some(
                self.client
                    .list::<Secret>(
                        self.search_ns_for_pod(selector),
                        &ListParams::default().labels(&label_selector),
                    )
                    .await
                    .context(SecretQuerySnafu)?
                    .into_iter()
                    .filter_map(|secret| secret.metadata.labels?.remove(LABEL_SCOPE_NODE))
                    .collect(),
            ))
        } else {
            Ok(None)
        }
    }
}

enum LabelSelectorPodInfo<'a> {
    Scheduling(&'a SchedulingPodInfo),
    Scheduled(&'a PodInfo),
}

fn build_selector_labels(
    vol_selector: &SecretVolumeSelector,
    pod_info: LabelSelectorPodInfo,
) -> Result<Labels, Error> {
    let mut labels: Labels =
        BTreeMap::from([(LABEL_CLASS.to_string(), vol_selector.class.to_string())])
            .try_into()
            .context(BuildLabelSnafu)?;
    let mut listener_i = 0;
    // Only include node selector once we are scheduled,
    // until then we use the query to decide where scheduling should be possible!
    if let LabelSelectorPodInfo::Scheduled(pod_info) = pod_info {
        // k8sSearch doesn't take the scope's resolved addresses into account, so we need to check whether
        // Listener scopes also imply Node
        if pod_info.scheduling.has_node_scope {
            labels
                .parse_insert((LABEL_SCOPE_NODE.to_string(), pod_info.node_name.clone()))
                .context(BuildLabelSnafu)?;
        }
    }
    let scheduling_pod_info = match pod_info {
        LabelSelectorPodInfo::Scheduling(spi) => spi,
        LabelSelectorPodInfo::Scheduled(pi) => &pi.scheduling,
    };
    for scope in &vol_selector.scope {
        match scope {
            SecretScope::Node => {
                // already checked `pod_info.has_node_scope`, which also takes node listeners into account
            }
            SecretScope::Pod => {
                labels
                    .parse_insert((LABEL_SCOPE_POD.to_string(), vol_selector.pod.clone()))
                    .context(BuildLabelSnafu)?;
            }
            SecretScope::Service { name } => {
                labels
                    .parse_insert((LABEL_SCOPE_SERVICE.to_string(), name.clone()))
                    .context(BuildLabelSnafu)?;
            }
            SecretScope::ListenerVolume { name } => {
                labels
                    .parse_insert((
                        format!("{LABEL_SCOPE_LISTENER}.{listener_i}"),
                        scheduling_pod_info
                            .volume_listener_names
                            .get(name)
                            .context(NoListenerSnafu {
                                listener_volume: name,
                            })?
                            .clone(),
                    ))
                    .context(BuildLabelSnafu)?;
                listener_i += 1;
            }
        }
    }
    Ok(labels)
}
