//! Support code for runtime-configurable dynamic [`SecretBackend`]s

use async_trait::async_trait;
use std::fmt::Display;

use super::{pod_info::PodInfo, SecretBackend, SecretBackendError};

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
        selector: super::SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<super::SecretFiles, Self::Error> {
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
