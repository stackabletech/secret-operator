use stackable_operator::{
    k8s_openapi::api::{apps::v1::Deployment, core::v1::EnvVar},
    kube::{
        ResourceExt,
        api::{DynamicObject, GroupVersionKind},
    },
};

use crate::data::containers;

/// Copy the environment from the "secret-operator-deployer" container in `source`
/// to *all* containers in target.
/// The target must be a DaemonSet or Deployment, otherwise this function is a no-op.
/// This function allows OLM Subscription objects to configure the environment
/// of operator containers.
pub(super) fn maybe_copy_env(
    source: &Deployment,
    target: &mut DynamicObject,
    target_gvk: &GroupVersionKind,
) -> anyhow::Result<()> {
    let target_kind_set = ["DaemonSet", "Deployment"];
    if target_kind_set.contains(&target_gvk.kind.as_str()) {
        if let Some(env) = deployer_env_var(source) {
            for container in containers(target)? {
                match container {
                    serde_json::Value::Object(c) => {
                        let json_env = env
                            .iter()
                            .map(|e| serde_json::json!(e))
                            .collect::<Vec<serde_json::Value>>();

                        match c.get_mut("env") {
                            Some(env) => match env {
                                v @ serde_json::Value::Null => {
                                    *v = serde_json::json!(json_env);
                                }
                                serde_json::Value::Array(container_env) => {
                                    container_env.extend_from_slice(&json_env)
                                }
                                _ => anyhow::bail!("env is not null or an array"),
                            },
                            None => {
                                c.insert("env".to_string(), serde_json::json!(json_env));
                            }
                        }
                    }
                    _ => anyhow::bail!("no containers found in object {}", target.name_any()),
                }
            }
        }
    }

    Ok(())
}

fn deployer_env_var(deployment: &Deployment) -> Option<&Vec<EnvVar>> {
    deployment
        .spec
        .as_ref()
        .and_then(|ds| ds.template.spec.as_ref())
        .map(|ts| ts.containers.iter())
        .into_iter()
        .flatten()
        .filter(|c| c.name == "secret-operator-deployer")
        .last()
        .and_then(|c| c.env.as_ref())
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use anyhow::Result;
    use serde::Deserialize;

    use super::*;

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
          env:
            - name: NAME1
              value: value1
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
          env:
            - name: NAME2
              value: value2
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

    #[test]
    fn test_copy_env_var() -> Result<()> {
        let gvk: GroupVersionKind = GroupVersionKind {
            kind: "DaemonSet".to_string(),
            version: "v1".to_string(),
            group: "apps".to_string(),
        };

        let mut daemonset = DAEMONSET.clone();

        maybe_copy_env(&DEPLOYMENT, &mut daemonset, &gvk)?;

        let expected = serde_json::json!(vec![
            EnvVar {
                name: "NAME1".to_string(),
                value: Some("value1".to_string()),
                ..EnvVar::default()
            },
            EnvVar {
                name: "NAME2".to_string(),
                value: Some("value2".to_string()),
                ..EnvVar::default()
            },
        ]);
        assert_eq!(
            containers(&mut daemonset)?
                .first()
                .expect("daemonset has no containers")
                .get("env")
                .unwrap(),
            &expected
        );
        Ok(())
    }
}
