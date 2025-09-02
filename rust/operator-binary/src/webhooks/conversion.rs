use serde::{Deserialize, Serialize};
use stackable_operator::{
    cli::OperatorEnvironmentOptions,
    kube::{Client, CustomResource},
    schemars::{self, JsonSchema},
    versioned::versioned,
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
) -> anyhow::Result<ConversionWebhookServer> {
    let crds_and_handlers = [
        (
            SecretClass::merged_crd(SecretClassVersion::V1Alpha1)?,
            SecretClass::try_convert as fn(_) -> _,
        ),
        (
            TrustStore::merged_crd(TrustStoreVersion::V1Alpha1)?,
            TrustStore::try_convert as fn(_) -> _,
        ),
        (
            Person::merged_crd(PersonVersion::V1Alpha1)?,
            Person::try_convert as fn(_) -> _,
        ),
    ];

    let options = ConversionWebhookOptions {
        socket_addr: format!("0.0.0.0:{CONVERSION_WEBHOOK_HTTPS_PORT}")
            .parse()
            .expect("static address is always valid"),
        field_manager: OPERATOR_NAME.to_owned(),
        namespace: operator_environment.operator_namespace,
        service_name: operator_environment.operator_service_name,
    };

    Ok(ConversionWebhookServer::new(crds_and_handlers, options, client).await?)
}

// !!! TESTING struct!!!
// !!! Will be removed later!!!
#[versioned(
    version(name = "v1alpha1"),
    version(name = "v1alpha2"),
    version(name = "v1beta1"),
    version(name = "v2"),
    version(name = "v3"),
    options(k8s(experimental_conversion_tracking)),
    crates(
        kube_core = "stackable_operator::kube::core",
        kube_client = "stackable_operator::kube::client",
        k8s_openapi = "stackable_operator::k8s_openapi",
        schemars = "stackable_operator::schemars",
        versioned = "stackable_operator::versioned",
    )
)]
pub mod versioned {
    #[versioned(crd(group = "test.stackable.tech", status = "PersonStatus",))]
    #[derive(Clone, Debug, CustomResource, Deserialize, JsonSchema, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct PersonSpec {
        username: String,

        // In v1alpha2 first and last name have been added
        #[versioned(added(since = "v1alpha2"))]
        first_name: String,

        #[versioned(added(since = "v1alpha2"))]
        last_name: String,

        // We started out with a enum. As we *need* to provide a default, we have a Unknown variant.
        // Afterwards we figured let's be more flexible and accept any arbitrary String.
        #[versioned(added(since = "v2"), changed(since = "v3", from_type = "Gender"))]
        gender: String,

        #[versioned(nested)]
        socials: Socials,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
    pub struct Socials {
        email: String,

        #[versioned(added(since = "v1beta1"))]
        mastodon: String,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct PersonStatus {
    pub alive: bool,
}

impl Default for PersonStatus {
    fn default() -> Self {
        Self { alive: true }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum Gender {
    #[default]
    Unknown,
    Male,
    Female,
}

impl From<Gender> for String {
    fn from(value: Gender) -> Self {
        match value {
            Gender::Unknown => "Unknown".to_owned(),
            Gender::Male => "Male".to_owned(),
            Gender::Female => "Female".to_owned(),
        }
    }
}

impl From<String> for Gender {
    fn from(value: String) -> Self {
        match value.as_str() {
            "Male" => Self::Male,
            "Female" => Self::Female,
            _ => Self::Unknown,
        }
    }
}
