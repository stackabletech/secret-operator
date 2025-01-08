use anyhow::{bail, Context, Result};
use clap::{crate_description, crate_version, Parser};
use stackable_operator::cli::Command;
use stackable_operator::client;
use stackable_operator::kube::api::{Api, DynamicObject, Patch, PatchParams, ResourceExt};
use stackable_operator::kube::discovery::{ApiResource, Discovery};

use stackable_operator::kube::core::GroupVersionKind;
use stackable_operator::logging;
use stackable_operator::utils;
use stackable_operator::utils::cluster_info::KubernetesClusterInfoOpts;

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

        // discovery (to be able to infer apis from kind/plural only)
        let discovery = Discovery::new(client.as_kube_client()).run().await?;

        for entry in walkdir::WalkDir::new(&dir) {
            match entry {
                Ok(manifest_file) => {
                    if manifest_file.file_type().is_file() {
                        let path = manifest_file.path();
                        tracing::info!("Applied manifest file: {}", path.display());
                        apply(path, &client, &discovery).await?;
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

async fn apply(
    pth: &std::path::Path,
    client: &client::Client,
    discovery: &Discovery,
) -> Result<()> {
    let ssapply = PatchParams::apply(APP_NAME).force();
    let yaml = std::fs::read_to_string(pth)
        .with_context(|| format!("Failed to read {}", pth.display()))?;
    for doc in multidoc_deserialize(&yaml)? {
        let obj: DynamicObject = serde_yaml::from_value(doc)?;
        let gvk = if let Some(tm) = &obj.types {
            GroupVersionKind::try_from(tm)?
        } else {
            bail!("cannot apply object without valid TypeMeta {:?}", obj);
        };
        let name = obj.name_any();
        if let Some((ar, _caps)) = discovery.resolve_gvk(&gvk) {
            let api = dynamic_api(ar, client);
            tracing::trace!("Applying {}: \n{}", gvk.kind, serde_yaml::to_string(&obj)?);
            let data: serde_json::Value = serde_json::to_value(&obj)?;
            let _r = api.patch(&name, &ssapply, &Patch::Apply(data)).await?;
            tracing::info!("applied {} {}", gvk.kind, name);
        } else {
            tracing::warn!("Cannot apply document for unknown {:?}", gvk);
        }
    }
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

fn dynamic_api(ar: ApiResource, client: &client::Client) -> Api<DynamicObject> {
    Api::default_namespaced_with(client.as_kube_client(), &ar)
}
