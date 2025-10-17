use std::{fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use stackable_operator::{
    cli::{MaintenanceOptions, OperatorEnvironmentOptions},
    kube::{Client, core::crd::MergeError},
    schemars::{self, JsonSchema},
    webhook::{
        maintainer::CustomResourceDefinitionMaintainer,
        servers::{ConversionWebhookError, ConversionWebhookServer},
    },
};

mod secret_class;
mod trust_store;

pub mod v1alpha1 {
    // NOTE (@Techassi): SecretClass v1alpha1 is unused and as such not exported.
    pub use crate::crd::trust_store::v1alpha1::*;
}

pub use secret_class::{SecretClass, SecretClassVersion};

pub mod v1alpha2 {
    pub use crate::crd::secret_class::v1alpha2::*;
}

use tokio::sync::oneshot;
pub use trust_store::{TrustStore, TrustStoreVersion};

use crate::FIELD_MANAGER;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidKerberosPrincipal {
    #[snafu(display(
        "principal contains illegal characters (allowed: alphanumeric, /, @, -, _, and .)"
    ))]
    IllegalCharacter,

    #[snafu(display("principal may not start with a dash"))]
    StartWithDash,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct KerberosPrincipal(String);

impl TryFrom<String> for KerberosPrincipal {
    type Error = InvalidKerberosPrincipal;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with('-') {
            invalid_kerberos_principal::StartWithDashSnafu.fail()
        } else if value.contains(|chr: char| {
            !chr.is_alphanumeric()
                && chr != '/'
                && chr != '@'
                && chr != '.'
                && chr != '-'
                && chr != '_'
        }) {
            invalid_kerberos_principal::IllegalCharacterSnafu.fail()
        } else {
            Ok(KerberosPrincipal(value))
        }
    }
}

impl From<KerberosPrincipal> for String {
    fn from(value: KerberosPrincipal) -> Self {
        value.0
    }
}

impl Display for KerberosPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for KerberosPrincipal {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Contains errors which can be encountered when creating the conversion webhook server and the
/// CRD maintainer.
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to merge CRD"))]
    MergeCrd { source: MergeError },

    #[snafu(display("failed to create conversion webhook server"))]
    CreateConversionWebhook { source: ConversionWebhookError },
}

/// Creates and returns a [`ConversionWebhookServer`] and a [`CustomResourceDefinitionMaintainer`].
pub async fn create_conversion_webhook_and_maintainer<'a>(
    operator_environment: &'a OperatorEnvironmentOptions,
    maintenance: &MaintenanceOptions,
    client: Client,
) -> Result<
    (
        ConversionWebhookServer,
        CustomResourceDefinitionMaintainer<'a>,
        oneshot::Receiver<()>,
    ),
    Error,
> {
    let crds_and_handlers = [
        (
            SecretClass::merged_crd(SecretClassVersion::V1Alpha2).context(MergeCrdSnafu)?,
            SecretClass::try_convert as fn(_) -> _,
        ),
        (
            TrustStore::merged_crd(TrustStoreVersion::V1Alpha1).context(MergeCrdSnafu)?,
            TrustStore::try_convert as fn(_) -> _,
        ),
    ];

    ConversionWebhookServer::with_maintainer(
        crds_and_handlers,
        &operator_environment.operator_service_name,
        &operator_environment.operator_namespace,
        FIELD_MANAGER,
        maintenance.disable_crd_maintenance,
        client,
    )
    .await
    .context(CreateConversionWebhookSnafu)
}
