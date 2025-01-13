use stackable_operator::k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use stackable_operator::k8s_openapi::api::core::v1::EnvVar;
use stackable_operator::kube::api::DynamicObject;

pub(super) fn maybe_copy_env(
    deployment: &Deployment,
    res: DynamicObject,
) -> anyhow::Result<DynamicObject> {
    let ds: anyhow::Result<DaemonSet, _> = res.clone().try_parse();
    match ds {
        Ok(mut daemonset) => {
            if let Some(ps) = daemonset
                .spec
                .as_mut()
                .and_then(|s| s.template.spec.as_mut())
            {
                for c in ps.containers.iter_mut() {
                    if c.name == "secret-operator" {
                        let d_env = deployment_env_var(deployment);
                        match c.env.as_mut() {
                            Some(c_env) => c_env.extend(d_env.into_iter()),
                            _ => c.env = Some(d_env),
                        }
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

fn deployment_env_var(deployment: &Deployment) -> Vec<EnvVar> {
    deployment
        .spec
        .as_ref()
        .and_then(|ds| ds.template.spec.as_ref())
        .map(|ts| ts.containers.iter())
        .into_iter()
        .flatten()
        .filter(|c| c.name == "secret-operator-deployer")
        .last()
        .and_then(|c| c.env.clone())
        .unwrap_or_default()
}
