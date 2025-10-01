use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    webhook::{
        servers::{ConversionWebhookOptions, ConversionWebhookServer},
        x509_cert::Certificate,
    },
};
use tokio::sync::mpsc;

use crate::crd::{SecretClass, SecretClassVersion, TrustStore, TrustStoreVersion};

pub async fn conversion_webhook(
    operator_environment: &OperatorEnvironmentOptions,
) -> anyhow::Result<(ConversionWebhookServer, mpsc::Receiver<Certificate>)> {
    let crds_and_handlers = [
        (
            SecretClass::merged_crd(SecretClassVersion::V1Alpha2)?,
            SecretClass::try_convert as fn(_) -> _,
        ),
        (
            TrustStore::merged_crd(TrustStoreVersion::V1Alpha1)?,
            TrustStore::try_convert as fn(_) -> _,
        ),
    ];

    let options = ConversionWebhookOptions {
        socket_addr: ConversionWebhookServer::DEFAULT_SOCKET_ADDRESS,
        namespace: operator_environment.operator_namespace.clone(),
        service_name: operator_environment.operator_service_name.clone(),
    };

    Ok(ConversionWebhookServer::new(crds_and_handlers, options).await?)
}
