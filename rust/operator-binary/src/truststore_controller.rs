use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use futures::StreamExt;
use kube_runtime::WatchStreamExt as _;
use snafu::Snafu;
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::{
        api::core::v1::{ConfigMap, Secret},
        ByteString,
    },
    kube::{
        api::PartialObjectMeta,
        core::DeserializeGuard,
        runtime::{
            controller,
            reflector::{self, ObjectRef},
            watcher, Controller,
        },
        Resource,
    },
    namespace::WatchNamespace,
};

use crate::{
    backend::{self, TrustSelector},
    crd::{self, SearchNamespace, SecretClass, TrustStore},
    format::well_known::CompatibilityOptions,
    utils::Flattened,
};

pub async fn start(client: &stackable_operator::client::Client, watch_namespace: &WatchNamespace) {
    let (secretclasses, secretclasses_writer) = reflector::store();
    let controller = Controller::new(
        watch_namespace.get_api::<DeserializeGuard<TrustStore>>(client),
        watcher::Config::default(),
    );
    let truststores = controller.store();
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
        // TODO: refactor...
        .watches(
            watch_namespace.get_api::<PartialObjectMeta<ConfigMap>>(client),
            watcher::Config::default(),
            {
                let truststores = truststores.clone();
                let secretclasses = secretclasses.clone();
                move |cm| {
                    let cm_namespace = cm.metadata.namespace.as_deref().unwrap();
                    let potentially_matching_secretclasses = secretclasses
                        .state()
                        .into_iter()
                        .filter_map(move |sc| {
                            sc.0.as_ref().ok().and_then(|sc| match &sc.spec.backend {
                                crd::SecretClassBackend::K8sSearch(backend) => {
                                    let name_matches =
                                        backend.trust_store_config_map_name == cm.metadata.name;
                                    (name_matches
                                        && backend
                                            .search_namespace
                                            .can_match_namespace(cm_namespace))
                                    .then(|| {
                                        (ObjectRef::from_obj(sc), backend.search_namespace.clone())
                                    })
                                }
                                crd::SecretClassBackend::AutoTls(_) => None,
                                crd::SecretClassBackend::CertManager(_) => None,
                                crd::SecretClassBackend::KerberosKeytab(_) => None,
                            })
                        })
                        .collect::<HashMap<ObjectRef<SecretClass>, SearchNamespace>>();
                    truststores
                        .state()
                        .into_iter()
                        .filter(move |ts| {
                            ts.0.as_ref().is_ok_and(|ts| {
                                let secret_class_ref =
                                    ObjectRef::<SecretClass>::new(&ts.spec.secret_class_name);
                                potentially_matching_secretclasses
                                    .get(&secret_class_ref)
                                    .is_some_and(|secret_class_ns| {
                                        secret_class_ns
                                            .resolve(ts.metadata.namespace.as_deref().unwrap())
                                            == cm.metadata.namespace.as_deref().unwrap()
                                    })
                            })
                        })
                        .map(|ts| ObjectRef::from_obj(&*ts))
                }
            },
        )
        .watches(
            watch_namespace.get_api::<PartialObjectMeta<Secret>>(client),
            watcher::Config::default(),
            move |secret| {
                let matching_secretclasses = secretclasses
                    .state()
                    .into_iter()
                    .filter_map(move |sc| {
                        sc.0.as_ref().ok().and_then(|sc| match &sc.spec.backend {
                            crd::SecretClassBackend::AutoTls(backend) => {
                                (backend.ca.secret == secret).then(|| ObjectRef::from_obj(sc))
                            }
                            crd::SecretClassBackend::K8sSearch(_) => None,
                            crd::SecretClassBackend::CertManager(_) => None,
                            crd::SecretClassBackend::KerberosKeytab(_) => None,
                        })
                    })
                    .collect::<HashSet<ObjectRef<SecretClass>>>();
                truststores
                    .state()
                    .into_iter()
                    .filter(move |ts| {
                        ts.0.as_ref().is_ok_and(|ts| {
                            let secret_class_ref =
                                ObjectRef::<SecretClass>::new(&ts.spec.secret_class_name);
                            matching_secretclasses.contains(&secret_class_ref)
                        })
                    })
                    .map(|ts| ObjectRef::from_obj(&*ts))
            },
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
    let (Flattened(string_data), Flattened(binary_data)) = trust_data
        .data
        .into_files(truststore.spec.format, &CompatibilityOptions::default())
        .unwrap()
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
            .unwrap()
            .build(),
        data: Some(string_data),
        binary_data: Some(binary_data),
        ..Default::default()
    };
    ctx.client
        .apply_patch("truststore", &trust_cm, &trust_cm)
        .await
        .unwrap();
    Ok(controller::Action::await_change())
}

fn error_policy(
    _obj: Arc<DeserializeGuard<TrustStore>>,
    _error: &Error,
    _ctx: Arc<Ctx>,
) -> controller::Action {
    controller::Action::requeue(Duration::from_secs(5))
}
