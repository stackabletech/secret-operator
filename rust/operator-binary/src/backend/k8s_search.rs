//! Queries the Kubernetes API for predefined [`Secret`] objects

use std::collections::{BTreeMap, HashSet};

use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::LabelSelector, ByteString,
    },
    kube::api::ListParams,
};

use crate::{crd::SearchNamespace, format::SecretData};

use super::{
    pod_info::PodInfo, scope::SecretScope, SecretBackend, SecretBackendError, SecretContents,
    SecretVolumeSelector,
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
}

impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::SecretSelector { .. } => tonic::Code::FailedPrecondition,
            Error::SecretQuery { .. } => tonic::Code::FailedPrecondition,
            Error::NoSecret { .. } => tonic::Code::FailedPrecondition,
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
        let label_selector = build_label_selector_query(selector, Some(&pod_info))?;
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
    ) -> Result<Option<HashSet<String>>, Self::Error> {
        if selector.scope.contains(&SecretScope::Node) {
            let label_selector = build_label_selector_query(selector, None)?;
            Ok(Some(
                self.client
                    .list::<Secret>(
                        __self.search_ns_for_pod(selector),
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

fn build_label_selector_query(
    vol_selector: &SecretVolumeSelector,
    pod_info: Option<&PodInfo>,
) -> Result<String, Error> {
    let mut label_selector =
        BTreeMap::from([(LABEL_CLASS.to_string(), vol_selector.class.to_string())]);
    for scope in &vol_selector.scope {
        match scope {
            SecretScope::Node => {
                if let Some(pod_info) = pod_info {
                    label_selector.insert(LABEL_SCOPE_NODE.to_string(), pod_info.node_name.clone());
                }
            }
            SecretScope::Pod => {
                label_selector.insert(LABEL_SCOPE_POD.to_string(), vol_selector.pod.clone());
            }
            SecretScope::Service { name } => {
                label_selector.insert(LABEL_SCOPE_SERVICE.to_string(), name.clone());
            }
            SecretScope::Listener { name } => {
                label_selector.insert(LABEL_SCOPE_LISTENER.to_string(), name.clone());
            }
        }
    }
    dbg!(&label_selector);
    stackable_operator::label_selector::convert_label_selector_to_query_string(&LabelSelector {
        match_expressions: None,
        match_labels: Some(label_selector),
    })
    .context(SecretSelectorSnafu)
}
