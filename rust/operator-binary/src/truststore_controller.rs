use std::{collections::HashMap, future::Future, sync::Arc, time::Duration};

use const_format::concatcp;
use futures::StreamExt;
use snafu::{OptionExt as _, ResultExt as _, Snafu};
use stackable_operator::{
    builder::meta::ObjectMetaBuilder,
    k8s_openapi::{
        ByteString,
        api::core::v1::{ConfigMap, Secret},
        apimachinery::pkg::apis::meta::v1::OwnerReference,
    },
    kube::{
        Resource,
        api::PartialObjectMeta,
        core::{DeserializeGuard, error_boundary},
        runtime::{
            Controller, WatchStreamExt as _, controller,
            events::{Recorder, Reporter},
            reflector::{self, Lookup, ObjectRef},
            watcher,
        },
    },
    logging::controller::{ReconcilerError, report_controller_reconciled},
    namespace::WatchNamespace,
};
use strum::{EnumDiscriminants, IntoStaticStr};

use crate::{
    OPERATOR_NAME,
    backend::{self, ProvisionParts, SecretBackendError, TrustSelector},
    crd::{v1alpha1, v1alpha2},
    format::{
        self,
        well_known::{CompatibilityOptions, NamingOptions},
    },
    utils::Flattened,
};

const CONTROLLER_NAME: &str = "truststore";
const FULL_CONTROLLER_NAME: &str = concatcp!(CONTROLLER_NAME, ".", OPERATOR_NAME);

pub async fn start<F>(
    client: stackable_operator::client::Client,
    watch_namespace: &WatchNamespace,
    shutdown_signal: F,
) where
    F: Future<Output = ()> + Send + Sync + 'static,
{
    let (secretclasses, secretclasses_writer) = reflector::store();
    let controller = Controller::new(
        watch_namespace.get_api::<DeserializeGuard<v1alpha1::TrustStore>>(&client),
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
                client.get_api::<DeserializeGuard<v1alpha2::SecretClass>>(&()),
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
            watch_namespace.get_api::<PartialObjectMeta<ConfigMap>>(&client),
            watcher::Config::default(),
        )
        // TODO: merge this into the other Secret watch
        .owns(
            watch_namespace.get_api::<PartialObjectMeta<Secret>>(&client),
            watcher::Config::default(),
        )
        .watches(
            watch_namespace.get_api::<PartialObjectMeta<ConfigMap>>(&client),
            watcher::Config::default(),
            secretclass_dependency_watch_mapper(
                truststores.clone(),
                secretclasses.clone(),
                |secretclass, cm| secretclass.spec.backend.refers_to_config_map(cm),
            ),
        )
        .watches(
            watch_namespace.get_api::<PartialObjectMeta<Secret>>(&client),
            watcher::Config::default(),
            secretclass_dependency_watch_mapper(
                truststores,
                secretclasses,
                |secretclass, secret| secretclass.spec.backend.refers_to_secret(secret),
            ),
        )
        .graceful_shutdown_on(shutdown_signal)
        .run(reconcile, error_policy, Arc::new(Ctx { client }))
        .for_each_concurrent(16, move |res| {
            let event_recorder = event_recorder.clone();
            async move {
                report_controller_reconciled(&event_recorder, FULL_CONTROLLER_NAME, &res).await
            }
        })
        .await;
}

/// Resolves modifications to dependencies of [`v1alpha2::SecretClass`] objects into
/// a list of affected [`v1alpha1::TrustStore`]s.
fn secretclass_dependency_watch_mapper<Dep: Resource, Conds>(
    truststores: reflector::Store<DeserializeGuard<v1alpha1::TrustStore>>,
    secretclasses: reflector::Store<DeserializeGuard<v1alpha2::SecretClass>>,
    reference_conditions: impl Copy + Fn(&v1alpha2::SecretClass, &Dep) -> Conds,
) -> impl Fn(Dep) -> Vec<ObjectRef<DeserializeGuard<v1alpha1::TrustStore>>>
where
    Conds: IntoIterator<Item = v1alpha2::SearchNamespaceMatchCondition>,
{
    move |dep| {
        let potentially_matching_secretclasses =
            secretclasses
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
                .collect::<HashMap<
                    ObjectRef<v1alpha2::SecretClass>,
                    Vec<v1alpha2::SearchNamespaceMatchCondition>,
                >>();
        truststores
            .state()
            .into_iter()
            .filter(move |ts| {
                ts.0.as_ref().is_ok_and(|ts| {
                    let Some(ts_namespace) = ts.metadata.namespace.as_deref() else {
                        return false;
                    };
                    let secret_class_ref =
                        ObjectRef::<v1alpha2::SecretClass>::new(&ts.spec.secret_class_name);
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

    #[snafu(display("failed to get {secret_class} for TrustStore"))]
    GetSecretClass {
        source: stackable_operator::client::Error,
        secret_class: ObjectRef<v1alpha2::SecretClass>,
    },

    #[snafu(display("failed to initialize SecretClass backend for {secret_class}"))]
    InitBackend {
        source: backend::dynamic::FromClassError,
        secret_class: ObjectRef<v1alpha2::SecretClass>,
    },

    #[snafu(display("failed to get trust data from backend"))]
    BackendGetTrustData { source: backend::dynamic::DynError },

    #[snafu(display("TrustStore has no associated Namespace"))]
    NoTrustStoreNamespace,

    #[snafu(display("TrustStore has no associated name"))]
    NoTrustStoreName,

    #[snafu(display("TrustStore has no associated UID"))]
    NoTrustStoreUid,

    #[snafu(display("failed to convert trust data into desired format"))]
    FormatData {
        source: format::IntoFilesError,
        secret_class: ObjectRef<v1alpha2::SecretClass>,
    },

    #[snafu(display("failed to build owner reference to the TrustStore"))]
    BuildOwnerReference {
        source: stackable_operator::builder::meta::Error,
    },

    #[snafu(display("failed to apply target {config_map} for the TrustStore"))]
    ApplyTrustStoreConfigMap {
        source: stackable_operator::client::Error,
        config_map: ObjectRef<ConfigMap>,
    },

    #[snafu(display("failed to apply target {secret} for the TrustStore"))]
    ApplyTrustStoreSecret {
        source: stackable_operator::client::Error,
        secret: ObjectRef<Secret>,
    },

    #[snafu(display(
        "failed to look up pre-existing target {object} before applying the TrustStore"
    ))]
    GetExistingTarget {
        source: stackable_operator::client::Error,
        object: ObjectRef<stackable_operator::kube::api::DynamicObject>,
    },

    #[snafu(display(
        "refusing to overwrite pre-existing {object} that is not owned by this TrustStore"
    ))]
    RefuseToOverwriteForeignTarget {
        object: ObjectRef<stackable_operator::kube::api::DynamicObject>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;
impl ReconcilerError for Error {
    fn category(&self) -> &'static str {
        ErrorDiscriminants::from(self).into()
    }

    fn secondary_object(&self) -> Option<ObjectRef<stackable_operator::kube::api::DynamicObject>> {
        match self {
            Error::InvalidTrustStore { .. } => None,
            Error::GetSecretClass { secret_class, .. } => Some(secret_class.clone().erase()),
            Error::InitBackend { secret_class, .. } => Some(secret_class.clone().erase()),
            Error::BackendGetTrustData { source } => source.secondary_object(),
            Error::NoTrustStoreNamespace => None,
            Error::NoTrustStoreName => None,
            Error::NoTrustStoreUid => None,
            Error::FormatData { secret_class, .. } => Some(secret_class.clone().erase()),
            Error::BuildOwnerReference { .. } => None,
            Error::ApplyTrustStoreConfigMap { config_map, .. } => Some(config_map.clone().erase()),
            Error::ApplyTrustStoreSecret { secret, .. } => Some(secret.clone().erase()),
            Error::GetExistingTarget { object, .. } => Some(object.clone()),
            Error::RefuseToOverwriteForeignTarget { object } => Some(object.clone()),
        }
    }
}

/// Returns `true` if `existing_owners` contain a controller `OwnerReference` that points to the
/// TrustStore with the given UID. Used to ensure we only overwrite output ConfigMaps and Secrets
/// that we previously created ourselves; refusing otherwise prevents the TrustStore primitive
/// from being abused to clobber foreign same-named objects (e.g. `kube-root-ca.crt`) via the
/// operator's elevated cluster-wide write permissions.
fn is_owned_by_truststore(existing_owners: &[OwnerReference], truststore_uid: &str) -> bool {
    let truststore_kind = <v1alpha1::TrustStore as Resource>::kind(&());
    existing_owners.iter().any(|owner| {
        owner.controller == Some(true)
            && owner.kind == truststore_kind
            && owner.api_version.starts_with("secrets.stackable.tech/")
            && owner.uid == truststore_uid
    })
}

/// Looks up a pre-existing object with the same name/namespace as the TrustStore output and fails
/// if it exists but is not controlled by this TrustStore. See [`is_owned_by_truststore`] for the
/// security rationale.
async fn ensure_existing_target_is_not_foreign<K>(
    client: &stackable_operator::client::Client,
    name: &str,
    namespace: &str,
    truststore_uid: &str,
    object_ref: ObjectRef<stackable_operator::kube::api::DynamicObject>,
) -> Result<()>
where
    K: stackable_operator::kube::Resource<DynamicType = ()>
        + stackable_operator::client::GetApi<Namespace = str>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned,
{
    let existing = client
        .get_opt::<K>(name, namespace)
        .await
        .with_context(|_| GetExistingTargetSnafu {
            object: object_ref.clone(),
        })?;
    if let Some(existing) = existing {
        let owners = existing.meta().owner_references.as_deref().unwrap_or(&[]);
        if !is_owned_by_truststore(owners, truststore_uid) {
            return RefuseToOverwriteForeignTargetSnafu { object: object_ref }.fail();
        }
    }
    Ok(())
}

struct Ctx {
    client: stackable_operator::client::Client,
}

async fn reconcile(
    truststore: Arc<DeserializeGuard<v1alpha1::TrustStore>>,
    ctx: Arc<Ctx>,
) -> Result<controller::Action> {
    let truststore = truststore
        .0
        .as_ref()
        .map_err(error_boundary::InvalidObject::clone)
        .context(InvalidTrustStoreSnafu)?;
    let secret_class_name = &truststore.spec.secret_class_name;
    let secret_class = ctx
        .client
        .get::<v1alpha2::SecretClass>(secret_class_name, &())
        .await
        .context(GetSecretClassSnafu {
            secret_class: ObjectRef::<v1alpha2::SecretClass>::new(secret_class_name),
        })?;
    let secret_class_ref = secret_class.to_object_ref(());
    let backend = backend::dynamic::from_class(&ctx.client, secret_class)
        .await
        .with_context(|_| InitBackendSnafu {
            secret_class: secret_class_ref.clone(),
        })?;
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
    let naming_options = NamingOptions {
        tls_pem_ca_name: truststore.spec.tls_pem_ca_name.clone(),
        ..Default::default()
    };
    let trust_file_contents = trust_data
        .data
        .into_files(
            truststore.spec.format,
            naming_options,
            CompatibilityOptions::default(),
            ProvisionParts::PublicPrivate,
        )
        .context(FormatDataSnafu {
            secret_class: secret_class_ref,
        })?;
    let (Flattened(string_data), Flattened(binary_data)) = trust_file_contents
        .into_iter()
        // Try to put valid UTF-8 data into `string_data`, but fall back to `binary_data` otherwise
        .map(|(k, v)| match String::from_utf8(v) {
            Ok(v) => (Some((k, v)), None),
            Err(v) => (None, Some((k, ByteString(v.into_bytes())))),
        })
        .collect();

    let trust_metadata = ObjectMetaBuilder::new()
        .name_and_namespace(truststore)
        .ownerreference_from_resource(truststore, None, Some(true))
        .context(BuildOwnerReferenceSnafu)?
        .build();

    let truststore_name = truststore
        .metadata
        .name
        .as_deref()
        .context(NoTrustStoreNameSnafu)?;
    let truststore_namespace = selector.namespace.as_str();
    let truststore_uid = truststore
        .metadata
        .uid
        .as_deref()
        .context(NoTrustStoreUidSnafu)?;

    match truststore.spec.target_kind {
        v1alpha1::TrustStoreOutputType::ConfigMap => {
            let trust_cm = ConfigMap {
                metadata: trust_metadata,
                data: Some(string_data),
                binary_data: Some(binary_data),
                ..Default::default()
            };
            ensure_existing_target_is_not_foreign::<ConfigMap>(
                &ctx.client,
                truststore_name,
                truststore_namespace,
                truststore_uid,
                ObjectRef::from_obj(&trust_cm).erase(),
            )
            .await?;
            ctx.client
                .apply_patch(CONTROLLER_NAME, &trust_cm, &trust_cm)
                .await
                .context(ApplyTrustStoreConfigMapSnafu {
                    config_map: &trust_cm,
                })?;
        }
        v1alpha1::TrustStoreOutputType::Secret => {
            let trust_secret = Secret {
                metadata: trust_metadata,
                string_data: Some(string_data),
                data: Some(binary_data),
                ..Default::default()
            };
            ensure_existing_target_is_not_foreign::<Secret>(
                &ctx.client,
                truststore_name,
                truststore_namespace,
                truststore_uid,
                ObjectRef::from_obj(&trust_secret).erase(),
            )
            .await?;
            ctx.client
                .apply_patch(CONTROLLER_NAME, &trust_secret, &trust_secret)
                .await
                .context(ApplyTrustStoreSecretSnafu {
                    secret: &trust_secret,
                })?;
        }
    }

    Ok(controller::Action::await_change())
}

fn error_policy(
    _obj: Arc<DeserializeGuard<v1alpha1::TrustStore>>,
    _error: &Error,
    _ctx: Arc<Ctx>,
) -> controller::Action {
    controller::Action::requeue(Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_ref(
        api_version: &str,
        kind: &str,
        uid: &str,
        controller: Option<bool>,
    ) -> OwnerReference {
        OwnerReference {
            api_version: api_version.to_string(),
            kind: kind.to_string(),
            name: "some-name".to_string(),
            uid: uid.to_string(),
            controller,
            block_owner_deletion: None,
        }
    }

    #[test]
    fn empty_owner_refs_are_rejected() {
        assert!(!is_owned_by_truststore(&[], "my-uid"));
    }

    #[test]
    fn matching_controller_owner_ref_is_accepted() {
        let owners = [owner_ref(
            "secrets.stackable.tech/v1alpha1",
            "TrustStore",
            "my-uid",
            Some(true),
        )];
        assert!(is_owned_by_truststore(&owners, "my-uid"));
    }

    #[test]
    fn non_controller_owner_ref_is_rejected() {
        let owners = [owner_ref(
            "secrets.stackable.tech/v1alpha1",
            "TrustStore",
            "my-uid",
            Some(false),
        )];
        assert!(!is_owned_by_truststore(&owners, "my-uid"));
    }

    #[test]
    fn different_uid_is_rejected() {
        let owners = [owner_ref(
            "secrets.stackable.tech/v1alpha1",
            "TrustStore",
            "other-uid",
            Some(true),
        )];
        assert!(!is_owned_by_truststore(&owners, "my-uid"));
    }

    #[test]
    fn different_kind_is_rejected() {
        let owners = [owner_ref("v1", "ConfigMap", "my-uid", Some(true))];
        assert!(!is_owned_by_truststore(&owners, "my-uid"));
    }

    #[test]
    fn foreign_api_group_is_rejected() {
        let owners = [owner_ref(
            "evil.example.com/v1",
            "TrustStore",
            "my-uid",
            Some(true),
        )];
        assert!(!is_owned_by_truststore(&owners, "my-uid"));
    }

    #[test]
    fn unrelated_controller_owner_ref_is_rejected() {
        let owners = [owner_ref(
            "apps/v1",
            "Deployment",
            "some-deployment-uid",
            Some(true),
        )];
        assert!(!is_owned_by_truststore(&owners, "my-uid"));
    }
}
