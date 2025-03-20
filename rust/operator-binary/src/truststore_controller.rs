use std::{collections::HashMap, sync::Arc, time::Duration};

use futures::StreamExt;
use kube_runtime::{
    events::{Recorder, Reporter},
    WatchStreamExt as _,
};
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::{
        api::core::v1::{ConfigMap, Secret},
        ByteString,
    },
    kube::{
        api::PartialObjectMeta,
        core::{error_boundary, DeserializeGuard},
        runtime::{
            controller,
            reflector::{self, ObjectRef},
            watcher, Controller,
        },
        Resource,
    },
    logging::controller::{report_controller_reconciled, ReconcilerError},
    namespace::WatchNamespace,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    backend::{self, TrustSelector},
    crd::{SearchNamespaceMatchCondition, SecretClass, TrustStore},
    format::{self, well_known::CompatibilityOptions},
    utils::Flattened,
    OPERATOR_NAME,
};

const CONTROLLER_NAME: &str = "truststore";
const FULL_CONTROLLER_NAME: &str = "truststore.secrets.stackable.tech";

pub async fn start(client: &stackable_operator::client::Client, watch_namespace: &WatchNamespace) {
    let (secretclasses, secretclasses_writer) = reflector::store();
    let controller = Controller::new(
        watch_namespace.get_api::<DeserializeGuard<TrustStore>>(client),
        watcher::Config::default(),
    );
    let truststores = controller.store();
    let event_recorder = Arc::new(Recorder::new(
        client.as_kube_client(),
        Reporter {
            controller: FULL_CONTROLLER_NAME.to_string(),
            instance: None,
        },
    ));
    controller
        .watches_stream(
            watcher(
                client.get_api::<DeserializeGuard<SecretClass>>(&()),
                watcher::Config::default(),
            )
            .reflect(secretclasses_writer)
            .touched_objects(),
            {
                let truststores = truststores.clone();
                move |secretclass| {
                    truststores
                        .state()
                        .into_iter()
                        .filter(move |ts| {
                            ts.0.as_ref().is_ok_and(|ts| {
                                Some(&ts.spec.secret_class_name) == secretclass.meta().name.as_ref()
                            })
                        })
                        .map(|ts| ObjectRef::from_obj(&*ts))
                }
            },
        )
        // TODO: merge this into the other ConfigMap watch
        .owns(
            watch_namespace.get_api::<PartialObjectMeta<ConfigMap>>(client),
            watcher::Config::default(),
        )
        .watches(
            watch_namespace.get_api::<PartialObjectMeta<ConfigMap>>(client),
            watcher::Config::default(),
            secretclass_dependency_watch_mapper(
                truststores.clone(),
                secretclasses.clone(),
                |secretclass, cm| secretclass.spec.backend.refers_to_config_map(cm),
            ),
        )
        .watches(
            watch_namespace.get_api::<PartialObjectMeta<Secret>>(client),
            watcher::Config::default(),
            secretclass_dependency_watch_mapper(
                truststores,
                secretclasses,
                |secretclass, secret| secretclass.spec.backend.refers_to_secret(secret),
            ),
        )
        .run(
            reconcile,
            error_policy,
            Arc::new(Ctx {
                client: client.clone(),
            }),
        )
        .for_each_concurrent(16, move |res| {
            let event_recorder = event_recorder.clone();
            async move {
                report_controller_reconciled(
                    &event_recorder,
                    &format!("{CONTROLLER_NAME}.{OPERATOR_NAME}"),
                    &res,
                )
                .await
            }
        })
        .await;
}

/// Resolves modifications to dependencies of [`SecretClass`] objects into
/// a list of affected [`TrustStore`]s.
fn secretclass_dependency_watch_mapper<Dep: Resource, Conds>(
    truststores: reflector::Store<DeserializeGuard<TrustStore>>,
    secretclasses: reflector::Store<DeserializeGuard<SecretClass>>,
    reference_conditions: impl Copy + Fn(&SecretClass, &Dep) -> Conds,
) -> impl Fn(Dep) -> Vec<ObjectRef<DeserializeGuard<TrustStore>>>
where
    Conds: IntoIterator<Item = SearchNamespaceMatchCondition>,
{
    move |dep| {
        let potentially_matching_secretclasses = secretclasses
            .state()
            .into_iter()
            .filter_map(move |sc| {
                sc.0.as_ref().ok().and_then(|sc| {
                    let conditions = reference_conditions(sc, &dep)
                        .into_iter()
                        .collect::<Vec<_>>();
                    (!conditions.is_empty()).then(|| (ObjectRef::from_obj(sc), conditions))
                })
            })
            .collect::<HashMap<ObjectRef<SecretClass>, Vec<SearchNamespaceMatchCondition>>>();
        truststores
            .state()
            .into_iter()
            .filter(move |ts| {
                ts.0.as_ref().is_ok_and(|ts| {
                    let Some(ts_namespace) = ts.metadata.namespace.as_deref() else {
                        return false;
                    };
                    let secret_class_ref =
                        ObjectRef::<SecretClass>::new(&ts.spec.secret_class_name);
                    potentially_matching_secretclasses
                        .get(&secret_class_ref)
                        .is_some_and(|conds| {
                            conds
                                .iter()
                                .any(|cond| cond.matches_pod_namespace(ts_namespace))
                        })
                })
            })
            .map(|ts| ObjectRef::from_obj(&*ts))
            .collect()
    }
}

#[derive(Debug, Snafu, EnumDiscriminants)]
#[strum_discriminants(derive(IntoStaticStr))]
pub enum Error {
    #[snafu(display("TrustStore object is invalid"))]
    InvalidTrustStore {
        source: error_boundary::InvalidObject,
    },

    #[snafu(display("failed to get SecretClass for TrustStore"))]
    GetSecretClass {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to initialize SecretClass backend"))]
    InitBackend {
        source: backend::dynamic::FromClassError,
    },

    #[snafu(display("failed to get trust data from backend"))]
    BackendGetTrustData { source: backend::dynamic::DynError },

    #[snafu(display("TrustStore has no associated Namespace"))]
    NoTrustStoreNamespace,

    #[snafu(display("failed to convert trust data into desired format"))]
    FormatData { source: format::IntoFilesError },

    #[snafu(display("failed to build owner reference to the TrustStore"))]
    BuildOwnerReference {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to apply ConfigMap for the TrustStore"))]
    ApplyTrustStoreConfigMap {
        source: stackable_operator::client::Error,
    },
}
type Result<T, E = Error> = std::result::Result<T, E>;
impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }

    fn secondary_object(&self) -> Option<ObjectRef<stackable_operator::kube::api::DynamicObject>> {
        // TODO
        None
    }
}

struct Ctx {
    client: stackable_operator::client::Client,
}

async fn reconcile(
    truststore: Arc<DeserializeGuard<TrustStore>>,
    ctx: Arc<Ctx>,
) -> Result<controller::Action> {
    let truststore = truststore
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidTrustStoreSnafu)?;
    let secret_class = ctx
        .client
        .get::<SecretClass>(&truststore.spec.secret_class_name, &())
        .await
        .context(GetSecretClassSnafu)?;
    let backend = backend::dynamic::from_class(&ctx.client, secret_class)
        .await
        .context(InitBackendSnafu)?;
    let selector = TrustSelector {
        namespace: truststore
            .metadata
            .namespace
            .clone()
            .context(NoTrustStoreNamespaceSnafu)?,
    };
    let trust_data = backend
        .get_trust_data(&selector)
        .await
        .context(BackendGetTrustDataSnafu)?;
    let (Flattened(string_data), Flattened(binary_data)) = trust_data
        .data
        .into_files(truststore.spec.format, &CompatibilityOptions::default())
        .context(FormatDataSnafu)?
        .into_iter()
        // Try to put valid UTF-8 data into `data`, but fall back to `binary_data` otherwise
        .map(|(k, v)| match String::from_utf8(v) {
            Ok(v) => (Some((k, v)), None),
            Err(v) => (None, Some((k, ByteString(v.into_bytes())))),
        })
        .collect();
    let trust_cm = ConfigMap {
        metadata: ObjectMetaBuilder::new()
            .name_and_namespace(truststore)
            .ownerreference_from_resource(truststore, None, Some(true))
            .context(BuildOwnerReferenceSnafu)?
            .build(),
        data: Some(string_data),
        binary_data: Some(binary_data),
        ..Default::default()
    };
    ctx.client
        .apply_patch(CONTROLLER_NAME, &trust_cm, &trust_cm)
        .await
        .context(ApplyTrustStoreConfigMapSnafu)?;
    Ok(controller::Action::await_change())
}

fn error_policy(
    _obj: Arc<DeserializeGuard<TrustStore>>,
    _error: &Error,
    _ctx: Arc<Ctx>,
) -> controller::Action {
    controller::Action::requeue(Duration::from_secs(5))
}
