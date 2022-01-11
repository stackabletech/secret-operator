use std::collections::BTreeMap;

use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{api::core::v1::Secret, apimachinery::pkg::apis::meta::v1::LabelSelector},
    kube::api::ListParams,
};

use super::{
    pod_info::PodInfo, SecretBackend, SecretBackendError, SecretFiles, SecretScope,
    SecretVolumeSelector,
};

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
}

#[async_trait]
impl SecretBackend for K8sSearch {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<SecretFiles, Self::Error> {
        let mut label_selector = BTreeMap::new();
        label_selector.insert("secrets.stackable.tech/type".to_string(), selector.ty);
        for scope in selector.scope {
            match scope {
                SecretScope::Node => {
                    label_selector.insert(
                        "secrets.stackable.tech/node".to_string(),
                        pod_info.node_name.clone(),
                    );
                }
                SecretScope::Pod => {
                    label_selector.insert(
                        "secrets.stackable.tech/pod".to_string(),
                        selector.pod.clone(),
                    );
                }
            }
        }
        let label_selector =
            stackable_operator::label_selector::convert_label_selector_to_query_string(
                &LabelSelector {
                    match_expressions: None,
                    match_labels: Some(label_selector),
                },
            )
            .context(SecretSelectorSnafu)?;
        let secret = self
            .client
            .list::<Secret>(
                Some(&selector.namespace),
                &ListParams::default().labels(&label_selector),
            )
            .await
            .context(SecretQuerySnafu)?
            .into_iter()
            .next()
            .context(NoSecretSnafu { label_selector })?;
        Ok(secret
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k.into(), v.0))
            .collect())
    }
}
