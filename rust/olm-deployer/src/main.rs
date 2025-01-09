// TODO:
//
// - get the deployment object for the olm helper
// - get the env, tolerations, etc from the deployment
// - filter out the secret daemonset from the given manifest files
// - add env, tolerations, etc to the daemonset
use anyhow::{bail, Context, Result};
use clap::{crate_description, crate_version, Parser};
use stackable_operator::cli::Command;
use stackable_operator::client;
use stackable_operator::kube::api::{Api, Patch, PatchParams, ResourceExt};
use stackable_operator::kube::discovery::{ApiResource, Discovery};

use stackable_operator::kube::core::GroupVersionKind;
use stackable_operator::logging;
use stackable_operator::utils;
use stackable_operator::utils::cluster_info::KubernetesClusterInfoOpts;
use stackable_operator::{
    k8s_openapi::{
        api::{
            apps::v1::{DaemonSet, Deployment},
            core::v1::Toleration,
        },
        Resource,
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
    const DAEMONSET: &str = r#"
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: secret-operator-daemonset
  labels:
    app.kubernetes.io/instance: secret-operator
    app.kubernetes.io/name: secret-operator
    app.kubernetes.io/version: "24.11.0"
    stackable.tech/vendor: Stackable
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: secret-operator
      app.kubernetes.io/instance: secret-operator
      stackable.tech/vendor: Stackable
  template:
    metadata:
      labels:
        app.kubernetes.io/name: secret-operator
        app.kubernetes.io/instance: secret-operator
        stackable.tech/vendor: Stackable
    spec:
      serviceAccountName: secret-operator-serviceaccount
      securityContext: {}
      containers:
        - name: secret-operator
          securityContext:
            privileged: true
            runAsUser: 0
          image: "quay.io/stackable/secret-operator@sha256:bb5063aa67336465fd3fa80a7c6fd82ac6e30ebe3ffc6dba6ca84c1f1af95bfe"
          imagePullPolicy: IfNotPresent
          resources:
            limits:
              cpu: 100m
              memory: 128Mi
            requests:
              cpu: 100m
              memory: 128Mi
          env:
            - name: CSI_ENDPOINT
              value: /csi/csi.sock
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  apiVersion: v1
                  fieldPath: spec.nodeName
            - name: PRIVILEGED
              value: "true"
          volumeMounts:
            - name: csi
              mountPath: /csi
            - name: mountpoint
              mountPath: /var/lib/kubelet/pods
              mountPropagation: Bidirectional
            - name: tmp
              mountPath: /tmp
        - name: external-provisioner
          image: "quay.io/stackable/sig-storage/csi-provisioner@sha256:dd730457133f619d8759269abcfa79d7aeb817e01ba7af2d3aa1417df406ea56"
          imagePullPolicy: IfNotPresent
          resources:
            limits:
              cpu: 100m
              memory: 128Mi
            requests:
              cpu: 100m
              memory: 128Mi
          args:
            - --csi-address=/csi/csi.sock
            - --feature-gates=Topology=true
            - --extra-create-metadata
          volumeMounts:
            - name: csi
              mountPath: /csi
        - name: node-driver-registrar
          image: "quay.io/stackable/sig-storage/csi-node-driver-registrar@sha256:8331d680e6c40c56909f436ea3126fdca39761cf87781cd2db8d05c9082b05f5"
          imagePullPolicy: IfNotPresent
          resources:
            limits:
              cpu: 100m
              memory: 128Mi
            requests:
              cpu: 100m
              memory: 128Mi
          args:
            - --csi-address=/csi/csi.sock
            - --kubelet-registration-path=/var/lib/kubelet/plugins/secrets.stackable.tech/csi.sock
          volumeMounts:
            - name: registration-sock
              mountPath: /registration
            - name: csi
              mountPath: /csi
      initContainers:
        - name: migrate-longer-csi-registration-path
          image: "quay.io/stackable/secret-operator@sha256:bb5063aa67336465fd3fa80a7c6fd82ac6e30ebe3ffc6dba6ca84c1f1af95bfe"
          imagePullPolicy: IfNotPresent
          resources:
            limits:
              cpu: 100m
              memory: 128Mi
            requests:
              cpu: 100m
              memory: 128Mi
          command:
            - /bin/bash
            - -euo
            - pipefail
            - -x
            - -c
            - |
              ls -la /registration
              echo "Removing old (long) CSI registration path"
              if [ -d "/registration/secrets.stackable.tech-reg.sock" ]; then rmdir /registration/secrets.stackable.tech-reg.sock; fi
              ls -la /registration
          volumeMounts:
            - name: registration-sock
              mountPath: /registration
          securityContext:
            runAsUser: 0
      volumes:
        - name: registration-sock
          hostPath:
            # node-driver-registrar appends a driver-unique filename to this path to avoid conflicts
            # see https://github.com/stackabletech/secret-operator/issues/229 for why this path should not be too long
            path: /var/lib/kubelet/plugins_registry
        - name: csi
          hostPath:
            path: /var/lib/kubelet/plugins/secrets.stackable.tech/
        - name: mountpoint
          hostPath:
            path: /var/lib/kubelet/pods/
        - name: tmp
          emptyDir: {}
"#;

    const DEPLOYMENT: &str = r#"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-operator-deployer
  labels:
    app.kubernetes.io/name: secret-operator-deployer
    app.kubernetes.io/instance: secret-operator-deployer
    stackable.tech/vendor: Stackable
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app.kubernetes.io/name: secret-operator-deployer
      app.kubernetes.io/instance: secret-operator-deployer
      stackable.tech/vendor: Stackable
  template:
    metadata:
      labels:
        app.kubernetes.io/name: secret-operator-deployer
        app.kubernetes.io/instance: secret-operator-deployer
    spec:
      serviceAccountName: secret-operator-deployer
      securityContext: {}
      containers:
        - name: secret-operator-deployer
          securityContext: {}
          image: "quay.io/stackable/tools@sha256:bb02df387d8f614089fe053373f766e21b7a9a1ad04cb3408059014cb0f1388e"
          imagePullPolicy: IfNotPresent
          command: ["/usr/bin/bash", "/manifests/deploy.sh"]
          env:
            - name: SOME_IMPORTANT_FEATURE_FLAG
              value: "turn-it-on"
            - name: OP_VERSION
              value: '24.11.0'
            - name: NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          resources:
            limits:
              cpu: 100m
              memory: 512Mi
            requests:
              cpu: 100m
              memory: 512Mi
          volumeMounts:
            - name: manifests
              mountPath: /manifests
      volumes:
        - name: manifests
          configMap:
            name: secret-operator-deployer-manifests
      tolerations:
        - key: keep-out
          value: "yes"
          operator: Equal
          effect: NoSchedule
    "#;

    #[test]
    fn test_copy_tolerations() -> Result<()> {
        let data = serde_yaml::Value::deserialize(serde_yaml::Deserializer::from_str(DEPLOYMENT))?;
        //let do_deployment: DynamicObject = serde_yaml::from_value(data)?;
        //let deployment: Deployment =do_deployment.try_parse()?;
        let deployment: Deployment = serde_yaml::from_value(data)?;

        let data = serde_yaml::Value::deserialize(serde_yaml::Deserializer::from_str(DAEMONSET))?;
        let daemonset: DynamicObject = serde_yaml::from_value(data)?;

        let daemonset = maybe_copy_tolerations(&deployment, daemonset)?;

        assert_eq!(
            daemonset_tolerations(&daemonset.try_parse::<DaemonSet>()?),
            deployment_tolerations(&deployment)
        );

        Ok(())
    }

    fn daemonset_tolerations(res: &DaemonSet) -> Option<&Vec<Toleration>> {
        res.spec
            .as_ref()
            .and_then(|s| s.template.spec.as_ref())
            .and_then(|ps| ps.tolerations.as_ref())
    }
}
