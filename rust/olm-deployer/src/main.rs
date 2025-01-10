use anyhow::{anyhow, bail, Context, Result};
use clap::{crate_description, crate_version, Parser};
use stackable_operator::cli::Command;
use stackable_operator::client;
use stackable_operator::kube::api::{Api, Patch, PatchParams, ResourceExt, TypeMeta};
use stackable_operator::kube::discovery::{ApiResource, Discovery, Scope};

use stackable_operator::k8s_openapi::api::rbac::v1::ClusterRole;
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use stackable_operator::kube;
use stackable_operator::kube::core::GroupVersionKind;
use stackable_operator::logging;
use stackable_operator::utils;
use stackable_operator::utils::cluster_info::KubernetesClusterInfoOpts;
use stackable_operator::{
    k8s_openapi::api::{
        apps::v1::{DaemonSet, Deployment},
        core::v1::Toleration,
    },
    kube::api::DynamicObject,
};

pub const APP_NAME: &str = "stkbl-secret-olm-deployer";
pub const ENV_VAR_LOGGING: &str = "STKBL_SECRET_OLM_DEPLOYER_LOG";

mod built_info {
    include!(concat!(env!("OUT_DIR"), "/built.rs"));
}

#[derive(clap::Parser)]
#[clap(author, version)]
struct Opts {
    #[clap(subcommand)]
    cmd: Command<OlmDeployerRun>,
}

#[derive(clap::Parser)]
struct OlmDeployerRun {
    #[arg(long, short)]
    namespace: String,
    #[arg(long, short)]
    dir: std::path::PathBuf,
    /// Tracing log collector system
    #[arg(long, env, default_value_t, value_enum)]
    pub tracing_target: logging::TracingTarget,
    #[command(flatten)]
    pub cluster_info_opts: KubernetesClusterInfoOpts,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    if let Command::Run(OlmDeployerRun {
        namespace,
        dir,
        tracing_target,
        cluster_info_opts,
    }) = opts.cmd
    {
        logging::initialize_logging(ENV_VAR_LOGGING, APP_NAME, tracing_target);
        utils::print_startup_string(
            crate_description!(),
            crate_version!(),
            built_info::GIT_VERSION,
            built_info::TARGET,
            built_info::BUILT_TIME_UTC,
            built_info::RUSTC_VERSION,
        );

        let client =
            client::initialize_operator(Some(APP_NAME.to_string()), &cluster_info_opts).await?;

        let deployment_api = client.get_api::<Deployment>(&namespace);
        let deployment: Deployment = deployment_api.get("secret-operator-deployer").await?;

        let cluster_role_api = client.get_all_api::<ClusterRole>();
        let cluster_role: ClusterRole = cluster_role_api.get("secret-operator-clusterrole").await?;

        let kube_client = client.as_kube_client();
        // discovery (to be able to infer apis from kind/plural only)
        let discovery = Discovery::new(kube_client.clone()).run().await?;

        for entry in walkdir::WalkDir::new(&dir) {
            match entry {
                Ok(manifest_file) => {
                    if manifest_file.file_type().is_file() {
                        // ----------
                        let path = manifest_file.path();
                        tracing::info!("Reading manifest file: {}", path.display());
                        let yaml = std::fs::read_to_string(path)
                            .with_context(|| format!("Failed to read {}", path.display()))?;
                        for doc in multidoc_deserialize(&yaml)? {
                            let obj: DynamicObject = serde_yaml::from_value(doc)?;
                            // ----------
                            let gvk = if let Some(tm) = &obj.types {
                                GroupVersionKind::try_from(tm)?
                            } else {
                                bail!("cannot apply object without valid TypeMeta {:?}", obj);
                            };
                            let (ar, caps) = discovery
                                .resolve_gvk(&gvk)
                                .context(anyhow!("cannot resolve GVK {:?}", gvk))?;
                            let api = dynamic_api(ar, &caps.scope, kube_client.clone(), &namespace);
                            // ---------- patch object
                            let obj = maybe_copy_tolerations(&deployment, obj)?;
                            let obj =
                                maybe_update_owner(obj, &caps.scope, &deployment, &cluster_role)?;
                            // TODO: patch namespace where needed
                            // TODO: add env vars
                            // ---------- apply
                            apply(&api, obj, &gvk.kind).await?
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading manifest file: {}", e);
                }
            }
        }
    }

    Ok(())
}

fn maybe_update_owner(
    dynamic_object: DynamicObject,
    scope: &Scope,
    deployment: &Deployment,
    cluster_role: &ClusterRole,
) -> Result<DynamicObject> {
    // TODO: skip SecurityContextConstraints ?
    let owner_ref = match scope {
        Scope::Cluster => {
            let tm = TypeMeta::resource::<ClusterRole>();
            OwnerReference {
                name: cluster_role.name_any(),
                uid: cluster_role.metadata.uid.clone().context(format!(
                    "ClusterRole [{}] has no uid",
                    cluster_role.name_any()
                ))?,
                kind: tm.kind,
                api_version: tm.api_version,
                ..OwnerReference::default()
            }
        }
        Scope::Namespaced => {
            let tm = TypeMeta::resource::<Deployment>();
            OwnerReference {
                name: deployment.name_any(),
                uid: deployment
                    .metadata
                    .uid
                    .clone()
                    .context(format!("Deployment [{}] has no uid", deployment.name_any()))?,
                kind: tm.kind,
                api_version: tm.api_version,
                ..OwnerReference::default()
            }
        }
    };

    let mut ret = dynamic_object.clone();
    match ret.metadata.owner_references {
        Some(ref mut ors) => ors.push(owner_ref),
        None => ret.metadata.owner_references = Some(vec![owner_ref]),
    }
    Ok(ret)
}

async fn apply(api: &Api<DynamicObject>, obj: DynamicObject, kind: &str) -> Result<()> {
    let name = obj.name_any();
    let ssapply = PatchParams::apply(APP_NAME).force();
    tracing::trace!("Applying {}: \n{}", kind, serde_yaml::to_string(&obj)?);
    let data: serde_json::Value = serde_json::to_value(&obj)?;
    let _r = api.patch(&name, &ssapply, &Patch::Apply(data)).await?;
    tracing::info!("applied {} {}", kind, name);
    Ok(())
}

fn multidoc_deserialize(data: &str) -> Result<Vec<serde_yaml::Value>> {
    use serde::Deserialize;
    let mut docs = vec![];
    for de in serde_yaml::Deserializer::from_str(data) {
        docs.push(serde_yaml::Value::deserialize(de)?);
    }
    Ok(docs)
}

fn dynamic_api(
    ar: ApiResource,
    scope: &Scope,
    client: kube::Client,
    ns: &str,
) -> Api<DynamicObject> {
    match scope {
        Scope::Cluster => Api::all_with(client, &ar),
        _ => Api::namespaced_with(client, ns, &ar),
    }
}

fn maybe_copy_tolerations(deployment: &Deployment, res: DynamicObject) -> Result<DynamicObject> {
    let ds: Result<DaemonSet, _> = res.clone().try_parse();
    match ds {
        Ok(mut daemonset) => {
            if let Some(dts) = deployment_tolerations(deployment) {
                if let Some(pod_spec) = daemonset
                    .spec
                    .as_mut()
                    .and_then(|s| s.template.spec.as_mut())
                {
                    match pod_spec.tolerations.as_mut() {
                        Some(ta) => ta.extend(dts.clone()),
                        _ => pod_spec.tolerations = Some(dts.clone()),
                    }
                }
            }

            // TODO: halp!! change this to a proper conversion.
            let ret: DynamicObject = serde_yaml::from_str(&serde_yaml::to_string(&daemonset)?)?;

            Ok(ret)
        }
        _ => Ok(res),
    }
}

fn deployment_tolerations(deployment: &Deployment) -> Option<&Vec<Toleration>> {
    deployment
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|ps| ps.tolerations.as_ref())
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use serde::Deserialize;

    use std::sync::LazyLock;

    static DAEMONSET: LazyLock<DynamicObject> = LazyLock::new(|| {
        const STR_DAEMONSET: &str = r#"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: secret-operator-daemonset
spec:
  template:
    spec:
      containers:
        - name: secret-operator
          image: "quay.io/stackable/secret-operator@sha256:bb5063aa67336465fd3fa80a7c6fd82ac6e30ebe3ffc6dba6ca84c1f1af95bfe"
"#;

        let data =
            serde_yaml::Value::deserialize(serde_yaml::Deserializer::from_str(STR_DAEMONSET))
                .unwrap();
        serde_yaml::from_value(data).unwrap()
    });

    static DEPLOYMENT: LazyLock<Deployment> = LazyLock::new(|| {
        const STR_DEPLOYMENT: &str = r#"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-operator-deployer
  uid: d9287d0a-3069-47c3-8c90-b714dc6d1af5
spec:
  template:
    spec:
      containers:
        - name: secret-operator-deployer
          image: "quay.io/stackable/tools@sha256:bb02df387d8f614089fe053373f766e21b7a9a1ad04cb3408059014cb0f1388e"
      tolerations:
        - key: keep-out
          value: "yes"
          operator: Equal
          effect: NoSchedule
    "#;

        let data =
            serde_yaml::Value::deserialize(serde_yaml::Deserializer::from_str(STR_DEPLOYMENT))
                .unwrap();
        serde_yaml::from_value(data).unwrap()
    });

    static CLUSTER_ROLE: LazyLock<ClusterRole> = LazyLock::new(|| {
        const STR_CLUSTER_ROLE: &str = r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-operator-clusterrole
  uid: d9287d0a-3069-47c3-8c90-b714dc6dddaa
rules:
  - apiGroups:
      - ""
    resources:
      - secrets
      - events
    verbs:
      - get
    "#;
        let data =
            serde_yaml::Value::deserialize(serde_yaml::Deserializer::from_str(STR_CLUSTER_ROLE))
                .unwrap();
        serde_yaml::from_value(data).unwrap()
    });

    #[test]
    fn test_copy_tolerations() -> Result<()> {
        let daemonset = maybe_copy_tolerations(&DEPLOYMENT, DAEMONSET.clone())?;

        assert_eq!(
            daemonset_tolerations(&daemonset.try_parse::<DaemonSet>()?),
            deployment_tolerations(&DEPLOYMENT)
        );
        Ok(())
    }

    #[test]
    fn test_namespaced_owner() -> Result<()> {
        let daemonset = maybe_update_owner(
            DAEMONSET.clone(),
            &Scope::Namespaced,
            &DEPLOYMENT,
            &CLUSTER_ROLE,
        )?;

        let expected = Some(vec![OwnerReference {
            uid: "d9287d0a-3069-47c3-8c90-b714dc6d1af5".to_string(),
            name: "secret-operator-deployer".to_string(),
            kind: "Deployment".to_string(),
            api_version: "apps/v1".to_string(),
            ..OwnerReference::default()
        }]);
        assert_eq!(daemonset.metadata.owner_references, expected);
        Ok(())
    }

    #[test]
    fn test_cluster_owner() -> Result<()> {
        let daemonset = maybe_update_owner(
            DAEMONSET.clone(),
            &Scope::Cluster,
            &DEPLOYMENT,
            &CLUSTER_ROLE,
        )?;

        let expected = Some(vec![OwnerReference {
            uid: "d9287d0a-3069-47c3-8c90-b714dc6dddaa".to_string(),
            name: "secret-operator-clusterrole".to_string(),
            kind: "ClusterRole".to_string(),
            api_version: "rbac.authorization.k8s.io/v1".to_string(),
            ..OwnerReference::default()
        }]);
        assert_eq!(daemonset.metadata.owner_references, expected);
        Ok(())
    }

    fn daemonset_tolerations(res: &DaemonSet) -> Option<&Vec<Toleration>> {
        res.spec
            .as_ref()
            .and_then(|s| s.template.spec.as_ref())
            .and_then(|ps| ps.tolerations.as_ref())
    }
}
