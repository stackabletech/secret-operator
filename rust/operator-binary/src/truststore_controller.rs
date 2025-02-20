use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use snafu::Snafu;
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::{api::core::v1::ConfigMap, ByteString},
    kube::{
        core::DeserializeGuard,
        runtime::{controller, watcher, Controller},
    },
    namespace::WatchNamespace,
};

use crate::{
    backend::{self, TrustSelector},
    crd::{SecretClass, TrustStore},
    format::well_known::CompatibilityOptions,
};

pub async fn start(client: &stackable_operator::client::Client, watch_namespace: &WatchNamespace) {
    Controller::new(
        watch_namespace.get_api::<DeserializeGuard<TrustStore>>(client),
        watcher::Config::default(),
    )
    .run(
        reconcile,
        error_policy,
        Arc::new(Ctx {
            client: client.clone(),
        }),
    )
    .for_each(|x| async move {
        println!("{x:?}");
    })
    .await;
}

#[derive(Debug, Snafu)]
pub enum Error {}
type Result<T, E = Error> = std::result::Result<T, E>;

struct Ctx {
    client: stackable_operator::client::Client,
}

async fn reconcile(
    truststore: Arc<DeserializeGuard<TrustStore>>,
    ctx: Arc<Ctx>,
) -> Result<controller::Action> {
    let truststore = truststore.0.as_ref().unwrap();
    let secret_class = ctx
        .client
        .get::<SecretClass>(&truststore.spec.secret_class_name, &())
        .await
        .unwrap();
    let backend = backend::dynamic::from_class(&ctx.client, secret_class)
        .await
        .unwrap();
    let selector = TrustSelector {
        namespace: truststore.metadata.namespace.clone().unwrap(),
    };
    let trust_data = backend.get_trust_data(&selector).await.unwrap();
    let trust_cm = ConfigMap {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(truststore)
            .build(),
        binary_data: Some(
            trust_data
                .data
                .into_files(truststore.spec.format, &CompatibilityOptions::default())
                .unwrap()
                .into_iter()
                .map(|(k, v)| (k, ByteString(v)))
                .collect(),
        ),
        ..Default::default()
    };
    ctx.client
        .apply_patch("truststore", &trust_cm, &trust_cm)
        .await
        .unwrap();
    // TODO: Configure watch instead
    Ok(controller::Action::requeue(Duration::from_secs(5)))
}

fn error_policy(
    _obj: Arc<DeserializeGuard<TrustStore>>,
    _error: &Error,
    _ctx: Arc<Ctx>,
) -> controller::Action {
    controller::Action::requeue(Duration::from_secs(5))
}
