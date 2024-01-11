//! Queries the Kubernetes API for predefined [`Secret`] objects

use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::LabelSelector, ByteString,
    },
    kube::api::ListParams,
    kvp::{Label, LabelError, LabelSelectorExt, Labels},
};

use crate::{crd::SearchNamespace, format::SecretData};

use super::{
    pod_info::{PodInfo, SchedulingPodInfo},
    scope::SecretScope,
    SecretBackend, SecretBackendError, SecretContents, SecretVolumeSelector,
};

const LABEL_CLASS: &str = "secrets.stackable.tech/class";
const LABEL_SCOPE_NODE: &str = "secrets.stackable.tech/node";
const LABEL_SCOPE_POD: &str = "secrets.stackable.tech/pod";
const LABEL_SCOPE_SERVICE: &str = "secrets.stackable.tech/service";
const LABEL_SCOPE_LISTENER: &str = "secrets.stackable.tech/listener";

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to build Secret selector"))]
    SecretSelector {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("failed to query for secrets"))]
    SecretQuery {
        source: stackable_operator::error::Error,
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
            Error::SecretSelector { .. } => tonic::Code::FailedPrecondition,
            Error::SecretQuery { .. } => tonic::Code::FailedPrecondition,
            Error::NoSecret { .. } => tonic::Code::FailedPrecondition,
            Error::NoListener { .. } => tonic::Code::FailedPrecondition,
            Error::BuildLabel { .. } => tonic::Code::FailedPrecondition,
        }
    }
}

pub struct K8sSearch {
    pub client: stackable_operator::client::Client,
    pub search_namespace: SearchNamespace,
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
        let label_selector =
            build_label_selector_query(selector, LabelSelectorPodInfo::Scheduled(&pod_info))?;
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
        if pod_info.has_node_scope {
            let label_selector =
                build_label_selector_query(selector, LabelSelectorPodInfo::Scheduling(&pod_info))?;
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

fn build_label_selector_query(
    vol_selector: &SecretVolumeSelector,
    pod_info: LabelSelectorPodInfo,
) -> Result<String, Error> {
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
            labels.insert(
                Label::try_from((LABEL_SCOPE_NODE.to_string(), pod_info.node_name.clone()))
                    .context(BuildLabelSnafu)?,
            );
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
                labels.insert(
                    Label::try_from((LABEL_SCOPE_POD.to_string(), vol_selector.pod.clone()))
                        .context(BuildLabelSnafu)?,
                );
            }
            SecretScope::Service { name } => {
                labels.insert(
                    Label::try_from((LABEL_SCOPE_SERVICE.to_string(), name.clone()))
                        .context(BuildLabelSnafu)?,
                );
            }
            SecretScope::ListenerVolume { name } => {
                labels.insert(
                    Label::try_from((
                        format!("{LABEL_SCOPE_LISTENER}.{listener_i}"),
                        scheduling_pod_info
                            .volume_listener_names
                            .get(name)
                            .context(NoListenerSnafu {
                                listener_volume: name,
                            })?
                            .clone(),
                    ))
                    .context(BuildLabelSnafu)?,
                );
                listener_i += 1;
            }
        }
    }
    let label_selector = LabelSelector {
        match_expressions: None,
        match_labels: Some(labels.into()),
    };

    label_selector
        .to_query_string()
        .context(SecretSelectorSnafu)
}
