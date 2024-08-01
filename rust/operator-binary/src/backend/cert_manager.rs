use std::collections::HashSet;

use async_trait::async_trait;
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{api::core::v1::Secret, ByteString},
    kube::api::ObjectMeta,
};

use crate::{crd::CertManagerIssuer, external_crd, format::SecretData, utils::Unloggable};

use super::{
    k8s_search::LABEL_SCOPE_NODE,
    pod_info::{Address, PodInfo, SchedulingPodInfo},
    scope::SecretScope,
    ScopeAddressesError, SecretBackend, SecretBackendError, SecretContents, SecretVolumeSelector,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to get addresses for scope {scope}"))]
    ScopeAddresses {
        source: ScopeAddressesError,
        scope: SecretScope,
    },

    #[snafu(display("failed to get secret"))]
    GetSecret {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to apply cert-manager Certificate"))]
    ApplyCertManagerCertificate {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to get cert-manager Certificate"))]
    GetCertManagerCertificate {
        source: stackable_operator::client::Error,
    },
}

impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::ScopeAddresses { .. } => tonic::Code::Unavailable,
            Error::GetSecret { .. } => tonic::Code::Unavailable,
            Error::GetCertManagerCertificate { .. } => tonic::Code::Unavailable,
            Error::ApplyCertManagerCertificate { .. } => tonic::Code::Unavailable,
        }
    }
}

#[derive(Debug)]
pub struct CertManager {
    // Not secret per se, but isn't Debug: https://github.com/stackabletech/secret-operator/issues/411
    pub client: Unloggable<stackable_operator::client::Client>,
    pub issuer: CertManagerIssuer,
}

#[async_trait]
impl SecretBackend for CertManager {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: &SecretVolumeSelector,
        pod_info: PodInfo,
    ) -> Result<SecretContents, Self::Error> {
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
        let cert = external_crd::cert_manager::Certificate {
            metadata: ObjectMeta {
                name: Some(cert_name.clone()),
                namespace: Some(selector.namespace.clone()),
                labels: Some([(LABEL_SCOPE_NODE.to_string(), pod_info.node_name)].into()),
                ..Default::default()
            },
            spec: external_crd::cert_manager::CertificateSpec {
                secret_name: cert_name.clone(),
                dns_names,
                ip_addresses,
                issuer_ref: external_crd::cert_manager::IssuerRef {
                    name: self.issuer.name.clone(),
                    kind: self.issuer.kind,
                },
            },
        };
        self.client
            .apply_patch("cert-manager", &cert, &cert)
            .await
            .context(ApplyCertManagerCertificateSnafu)?;

        let secret = self
            .client
            .get::<Secret>(cert_name, &selector.namespace)
            .await
            .context(GetSecretSnafu)?;
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
            let cert_name = &selector.internal.pvc_name;
            Ok(self
                .client
                // If certificate does not already exist, allow scheduling to any node
                .get_opt::<external_crd::cert_manager::Certificate>(cert_name, &selector.namespace)
                .await
                .context(GetCertManagerCertificateSnafu)?
                .and_then(|cert| cert.metadata.labels?.remove(LABEL_SCOPE_NODE))
                .map(|node| [node].into()))
        } else {
            Ok(None)
        }
    }
}
