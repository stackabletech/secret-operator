//! Support code for runtime-configurable dynamic [`SecretBackend`]s

use async_trait::async_trait;
use snafu::Snafu;
use std::fmt::Display;

use super::{pod_info::PodInfo, SecretBackend, SecretBackendError};
use crate::crd::{self, SecretClass};

#[derive(Debug)]
pub struct DynError(Box<dyn SecretBackendError>);

impl Display for DynError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for DynError {
    fn source(&self) -> Option<&(dyn snafu::Error + 'static)> {
        self.0.source()
    }
}
impl SecretBackendError for DynError {
    fn grpc_code(&self) -> tonic::Code {
        self.0.grpc_code()
    }
}

pub struct DynamicAdapter<B>(B);

#[async_trait]
impl<B: SecretBackend + Send + Sync> SecretBackend for DynamicAdapter<B> {
    type Error = DynError;

    async fn get_secret_data(
        &self,
        selector: &super::SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<super::SecretContents, Self::Error> {
        self.0
            .get_secret_data(selector, pod_info)
            .await
            .map_err(|err| DynError(Box::new(err)))
    }
}

pub type Dynamic = dyn SecretBackend<Error = DynError>;
pub fn from(backend: impl SecretBackend + 'static) -> Box<Dynamic> {
    Box::new(DynamicAdapter(backend))
}

#[derive(Debug, Snafu)]
pub enum FromClassError {
    #[snafu(display("failed to initialize TLS backend"), context(false))]
    Tls { source: super::tls::Error },
}

impl SecretBackendError for FromClassError {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            FromClassError::Tls { source } => source.grpc_code(),
        }
    }
}

pub async fn from_class(
    client: &stackable_operator::client::Client,
    class: SecretClass,
) -> Result<Box<Dynamic>, FromClassError> {
    Ok(match class.spec.backend {
        crd::SecretClassBackend::K8sSearch(crd::K8sSearchBackend {
            search_namespace,
            secret_labels,
        }) => from(super::K8sSearch {
            client: client.clone(),
            search_namespace,
            secret_labels,
        }),
        crd::SecretClassBackend::AutoTls(crd::AutoTlsBackend {
            ca:
                crd::AutoTlsCa {
                    secret,
                    auto_generate,
                },
        }) => from(
            super::TlsGenerate::get_or_create_k8s_certificate(client, &secret, auto_generate)
                .await?,
        ),
    })
}
