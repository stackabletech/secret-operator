use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    kube::Client,
    webhook::{
        constants::CONVERSION_WEBHOOK_HTTPS_PORT,
        servers::{ConversionWebhookOptions, ConversionWebhookServer},
    },
};

use crate::{
    OPERATOR_NAME,
    crd::{SecretClass, SecretClassVersion, TrustStore, TrustStoreVersion},
};

pub async fn conversion_webhook(
    client: Client,
    operator_environment: OperatorEnvironmentOptions,
    disable_crd_management: bool,
) -> anyhow::Result<ConversionWebhookServer> {
    let crds_and_handlers = [
        (
            SecretClass::merged_crd(SecretClassVersion::V1Alpha2)?,
            SecretClass::try_convert as fn(_) -> _,
        ),
        (
            TrustStore::merged_crd(TrustStoreVersion::V1Alpha2)?,
            TrustStore::try_convert as fn(_) -> _,
        ),
    ];

    let options = ConversionWebhookOptions {
        socket_addr: format!("0.0.0.0:{CONVERSION_WEBHOOK_HTTPS_PORT}")
            .parse()
            .expect("static address is always valid"),
        field_manager: OPERATOR_NAME.to_owned(),
        namespace: operator_environment.operator_namespace,
        service_name: operator_environment.operator_service_name,
        maintain_crds: !disable_crd_management,
    };

    Ok(ConversionWebhookServer::new(crds_and_handlers, options, client).await?)
}
