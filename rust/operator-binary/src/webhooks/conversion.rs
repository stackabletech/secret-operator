use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    kube::{Client, core::crd::MergeError},
    webhook::{
        WebhookServer, WebhookServerError, WebhookServerOptions,
        webhooks::{ConversionWebhook, ConversionWebhookOptions},
    },
};
use tokio::sync::oneshot;

use crate::{
    FIELD_MANAGER,
    crd::{SecretClass, SecretClassVersion, TrustStore, TrustStoreVersion},
};

/// Contains errors which can be encountered when creating the conversion webhook server and the
/// CRD maintainer.
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to merge CRD"))]
    MergeCrd { source: MergeError },

    #[snafu(display("failed to create conversion webhook server"))]
    CreateWebhookServer { source: WebhookServerError },
}

/// Creates and returns a [`ConversionWebhookServer`] and a [`CustomResourceDefinitionMaintainer`].
pub async fn create_webhook_server(
    operator_environment: &OperatorEnvironmentOptions,
    disable_crd_maintenance: bool,
    client: Client,
) -> Result<(WebhookServer, oneshot::Receiver<()>), Error> {
    let crds_and_handlers = vec![
        (
            SecretClass::merged_crd(SecretClassVersion::V1Alpha2).context(MergeCrdSnafu)?,
            SecretClass::try_convert as fn(_) -> _,
        ),
        (
            TrustStore::merged_crd(TrustStoreVersion::V1Alpha1).context(MergeCrdSnafu)?,
            TrustStore::try_convert as fn(_) -> _,
        ),
    ];

    let conversion_webhook_options = ConversionWebhookOptions {
        disable_crd_maintenance,
        field_manager: FIELD_MANAGER.to_owned(),
    };
    let (conversion_webhook, initial_reconcile_rx) =
        ConversionWebhook::new(crds_and_handlers, client, conversion_webhook_options);

    let webhook_options = WebhookServerOptions {
        socket_addr: WebhookServer::DEFAULT_SOCKET_ADDRESS,
        webhook_namespace: operator_environment.operator_namespace.to_owned(),
        webhook_service_name: operator_environment.operator_service_name.to_owned(),
    };
    let webhook_server = WebhookServer::new(vec![Box::new(conversion_webhook)], webhook_options)
        .await
        .context(CreateWebhookServerSnafu)?;

    Ok((webhook_server, initial_reconcile_rx))
}
