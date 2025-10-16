//! Support code for runtime-configurable dynamic [`SecretBackend`]s

use std::{
    collections::HashSet,
    fmt::{Debug, Display},
};

use async_trait::async_trait;
use snafu::{ResultExt, Snafu};
use stackable_operator::kube::runtime::reflector::ObjectRef;

use super::{
    SecretBackend, SecretBackendError, SecretVolumeSelector,
    kerberos_keytab::{self, KerberosProfile},
    pod_info::{PodInfo, SchedulingPodInfo},
    tls,
};
use crate::{crd::v1alpha2, utils::Unloggable};

pub struct DynError(Box<dyn SecretBackendError>);

impl Debug for DynError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl Display for DynError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
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

    fn secondary_object(&self) -> Option<ObjectRef<stackable_operator::kube::api::DynamicObject>> {
        self.0.secondary_object()
    }
}

pub struct DynamicAdapter<B>(B);

impl<B: Debug> Debug for DynamicAdapter<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

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

    async fn get_trust_data(
        &self,
        selector: &super::TrustSelector,
    ) -> Result<super::SecretContents, Self::Error> {
        self.0
            .get_trust_data(selector)
            .await
            .map_err(|err| DynError(Box::new(err)))
    }

    async fn get_qualified_node_names(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: SchedulingPodInfo,
    ) -> Result<Option<HashSet<String>>, Self::Error> {
        self.0
            .get_qualified_node_names(selector, pod_info)
            .await
            .map_err(|err| DynError(Box::new(err)))
    }
}

pub type Dynamic = dyn SecretBackend<Error = DynError>;
pub fn from(backend: impl SecretBackend + 'static) -> Box<Dynamic> {
    Box::new(DynamicAdapter(backend))
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromClassError {
    #[snafu(display("failed to initialize TLS backend"), context(false))]
    Tls { source: tls::Error },

    #[snafu(
        display("failed to initialize Kerberos Keytab backend"),
        context(false)
    )]
    KerberosKeytab { source: kerberos_keytab::Error },
}

impl SecretBackendError for FromClassError {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            FromClassError::Tls { source } => source.grpc_code(),
            FromClassError::KerberosKeytab { source } => source.grpc_code(),
        }
    }

    fn secondary_object(&self) -> Option<ObjectRef<stackable_operator::kube::api::DynamicObject>> {
        match self {
            FromClassError::Tls { source } => source.secondary_object(),
            FromClassError::KerberosKeytab { source } => source.secondary_object(),
        }
    }
}

pub async fn from_class(
    client: &stackable_operator::client::Client,
    class: v1alpha2::SecretClass,
) -> Result<Box<Dynamic>, FromClassError> {
    Ok(match class.spec.backend {
        v1alpha2::SecretClassBackend::K8sSearch(v1alpha2::K8sSearchBackend {
            search_namespace,
            trust_store_config_map_name,
        }) => from(super::K8sSearch {
            client: Unloggable(client.clone()),
            search_namespace,
            trust_store_config_map_name,
        }),
        v1alpha2::SecretClassBackend::AutoTls(v1alpha2::AutoTlsBackend {
            ca,
            additional_trust_roots,
            max_certificate_lifetime,
        }) => from(
            super::TlsGenerate::get_or_create_k8s_certificate(
                client,
                &ca,
                &additional_trust_roots,
                max_certificate_lifetime,
            )
            .await?,
        ),
        v1alpha2::SecretClassBackend::CertManager(config) => from(super::CertManager {
            client: Unloggable(client.clone()),
            config,
        }),
        v1alpha2::SecretClassBackend::KerberosKeytab(v1alpha2::KerberosKeytabBackend {
            realm_name,
            kdc,
            admin,
            admin_keytab_secret,
            admin_principal,
        }) => from(
            super::KerberosKeytab::new_from_k8s_keytab(
                client,
                KerberosProfile {
                    realm_name,
                    kdc,
                    admin,
                },
                &admin_keytab_secret,
                admin_principal,
            )
            .await?,
        ),
    })
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FromSelectorError {
    #[snafu(display("failed to get {class}"))]
    GetSecretClass {
        source: stackable_operator::client::Error,
        class: ObjectRef<v1alpha2::SecretClass>,
    },

    #[snafu(display("failed to initialize backend for {class}"))]
    FromClass {
        #[snafu(source(from(FromClassError, Box::new)))]
        source: Box<FromClassError>,
        class: ObjectRef<v1alpha2::SecretClass>,
    },
}

impl SecretBackendError for FromSelectorError {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            FromSelectorError::GetSecretClass { .. } => tonic::Code::Unavailable,
            FromSelectorError::FromClass { source, .. } => source.grpc_code(),
        }
    }

    fn secondary_object(&self) -> Option<ObjectRef<stackable_operator::kube::api::DynamicObject>> {
        match self {
            FromSelectorError::GetSecretClass { class, .. } => Some(class.clone().erase()),
            FromSelectorError::FromClass { source, class } => source
                .secondary_object()
                .or_else(|| Some(class.clone().erase())),
        }
    }
}

pub async fn from_selector(
    client: &stackable_operator::client::Client,
    selector: &SecretVolumeSelector,
) -> Result<Box<Dynamic>, FromSelectorError> {
    let class_ref = || ObjectRef::new(&selector.class);
    let class = client
        .get::<v1alpha2::SecretClass>(&selector.class, &())
        .await
        .with_context(|_| from_selector_error::GetSecretClassSnafu { class: class_ref() })?;
    from_class(client, class)
        .await
        .with_context(|_| from_selector_error::FromClassSnafu { class: class_ref() })
}
