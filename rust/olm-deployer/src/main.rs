/// This program acts as a proxy Deployment in OLM environments that installs the secret operator.
/// The operator manifests are read from a directory and patched before being submitted to the
/// control plane.
/// It expects the following objects to exist (they are created by OLM) and uses them as
/// sources for patch data:
/// - A Deployment named "secret-operator-deployer" in the target namespace.
/// - A ClusterRole owned by the same CSV that deployed this tool.
///
/// See the documentation of the `maybe_*` functions for patching details.
///
/// The `keep-alive` cli option prevents the program from finishing and thus for OLM
/// to observe it as a failure.
///
mod data;
mod env;
mod namespace;
mod owner;
mod resources;
mod tolerations;

use anyhow::{anyhow, bail, Context, Result};
use clap::{crate_description, crate_version, Parser};
use stackable_operator::{
    cli::Command,
    client,
    k8s_openapi::api::{apps::v1::Deployment, rbac::v1::ClusterRole},
    kube,
    kube::{
        api::{Api, DynamicObject, ListParams, Patch, PatchParams, ResourceExt},
        core::GroupVersionKind,
        discovery::{ApiResource, Discovery, Scope},
    },
    logging, utils,
    utils::cluster_info::KubernetesClusterInfoOpts,
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
    #[arg(
        long,
        short,
        default_value = "false",
        help = "Keep running after manifests have been successfully applyed."
    )]
    keep_alive: bool,
    #[arg(
        long,
        short,
        help = "Name of ClusterServiceVersion object that owns this Deployment."
    )]
    csv: String,
    #[arg(long, short, help = "Namespace of the ClusterServiceVersion object.")]
    namespace: String,
    #[arg(long, short, help = "Directory with manifests to patch and apply.")]
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
        keep_alive,
        csv,
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

        let deployment = get_deployment(&csv, &namespace, &client).await?;
        let cluster_role = get_cluster_role(&csv, &client).await?;

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
                            let mut obj: DynamicObject = serde_yaml::from_value(doc)?;
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
                            tolerations::maybe_copy_tolerations(&deployment, &mut obj, &gvk)?;
                            owner::maybe_update_owner(
                                &mut obj,
                                &caps.scope,
                                &deployment,
                                &cluster_role,
                            )?;
                            namespace::maybe_patch_namespace(&namespace, &mut obj, &gvk)?;
                            env::maybe_copy_env(&deployment, &mut obj, &gvk)?;
                            resources::maybe_copy_resources(&deployment, &mut obj, &gvk)?;
                            // ---------- apply
                            apply(&api, obj, &gvk.kind).await?
                        }
                    }
                }
                Err(e) => {
                    bail!("Error reading manifest file: {}", e);
                }
            }
        }

        if keep_alive {
            // keep the pod running
            tokio::time::sleep(std::time::Duration::from_secs(u64::MAX)).await;
        }
    }

    Ok(())
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

async fn get_cluster_role(csv: &str, client: &client::Client) -> Result<ClusterRole> {
    let labels = format!("olm.owner={csv},olm.owner.kind=ClusterServiceVersion");
    let lp = ListParams {
        label_selector: Some(labels.clone()),
        ..ListParams::default()
    };

    let cluster_role_api = client.get_all_api::<ClusterRole>();
    let result = cluster_role_api.list(&lp).await?.items;
    if !result.is_empty() {
        Ok(result.first().unwrap().clone())
    } else {
        bail!("ClusterRole object not found for labels {labels}")
    }
}

async fn get_deployment(csv: &str, namespace: &str, client: &client::Client) -> Result<Deployment> {
    let labels = format!("olm.owner={csv},olm.owner.kind=ClusterServiceVersion");
    let lp = ListParams {
        label_selector: Some(labels.clone()),
        ..ListParams::default()
    };

    let deployment_api = client.get_api::<Deployment>(namespace);
    let result = deployment_api.list(&lp).await?.items;

    match result.len() {
        0 => bail!("no deployment owned by the csv {csv} found in namespace {namespace}"),
        1 => Ok(result.first().unwrap().clone()),
        _ => bail!("multiple deployments owned by the csv {csv} found but only one was expected"),
    }
}
