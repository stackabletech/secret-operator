use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};

use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::{Pod, Secret},
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    },
    kube::{api::ListParams, runtime::reflector::ObjectRef},
};

use super::{SecretBackend, SecretBackendError, SecretScope};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to find {pod} owning the volume"))]
    OwnerPodNotFound {
        source: stackable_operator::error::Error,
        pod: ObjectRef<Pod>,
    },
    #[snafu(display("owner {pod} has no associated node"))]
    OwnerPodHasNoNode { pod: ObjectRef<Pod> },
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
            Error::OwnerPodNotFound { .. } => tonic::Code::FailedPrecondition,
            Error::OwnerPodHasNoNode { .. } => tonic::Code::FailedPrecondition,
            Error::SecretSelector { .. } => tonic::Code::FailedPrecondition,
            Error::SecretQuery { .. } => tonic::Code::FailedPrecondition,
            Error::NoSecret { .. } => tonic::Code::FailedPrecondition,
        }
    }
}

pub struct K8sSearch {
    pub client: stackable_operator::client::Client,
}

type SecretFiles = HashMap<PathBuf, Vec<u8>>;

#[async_trait]
impl SecretBackend for K8sSearch {
    type Error = Error;

    async fn get_secret_data(
        &self,
        sel: super::SecretVolumeSelector,
    ) -> Result<SecretFiles, Self::Error> {
        let pod_ref = ObjectRef::new(&sel.pod).within(&sel.namespace);
        let pod = self
            .client
            .get::<Pod>(&sel.pod, Some(&sel.namespace))
            .await
            .with_context(|_| OwnerPodNotFoundSnafu {
                pod: pod_ref.clone(),
            })?;
        let mut label_selector = BTreeMap::new();
        label_selector.insert("secrets.stackable.tech/type".to_string(), sel.ty);
        for scope in sel.scope {
            match scope {
                SecretScope::Node => {
                    label_selector.insert(
                        "secrets.stackable.tech/node".to_string(),
                        pod.spec
                            .as_ref()
                            .and_then(|pod_spec| pod_spec.node_name.clone())
                            .with_context(|| OwnerPodHasNoNodeSnafu {
                                pod: pod_ref.clone(),
                            })?,
                    );
                }
                SecretScope::Pod => {
                    label_selector
                        .insert("secrets.stackable.tech/pod".to_string(), sel.pod.clone());
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
                Some(&sel.namespace),
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
