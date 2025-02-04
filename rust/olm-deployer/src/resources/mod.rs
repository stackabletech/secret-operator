use stackable_operator::{
    k8s_openapi::api::{apps::v1::Deployment, core::v1::ResourceRequirements},
    kube::{
        api::{DynamicObject, GroupVersionKind},
        ResourceExt,
    },
};

use crate::data::container;

/// Copies the resources of the container named "secret-operator-deployer" from `source`
/// to the container "secret-operator" in `target`.
/// Does nothing if there are no resources or if the `target` is not a DaemonSet.
pub(super) fn maybe_copy_resources(
    source: &Deployment,
    target: &mut DynamicObject,
    target_gvk: &GroupVersionKind,
) -> anyhow::Result<()> {
    if target_gvk.kind == "DaemonSet" {
        if let Some(res) = deployment_resources(source) {
            match container(target, "secret-operator")? {
                serde_json::Value::Object(c) => {
                    c.insert("resources".to_string(), serde_json::json!(res));
                }
                _ => anyhow::bail!("no containers found in object {}", target.name_any()),
            }
        }
    }

    Ok(())
}

fn deployment_resources(deployment: &Deployment) -> Option<&ResourceRequirements> {
    deployment
        .spec
        .as_ref()
        .and_then(|ds| ds.template.spec.as_ref())
        .map(|ts| ts.containers.iter())
        .into_iter()
        .flatten()
        .filter(|c| c.name == "secret-operator-deployer")
        .last()
        .and_then(|c| c.resources.as_ref())
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use anyhow::Result;
    use serde::Deserialize;
    use stackable_operator::k8s_openapi::apimachinery::pkg::api::resource::Quantity;

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
          resources:
            limits:
              cpu: 500m
              memory: 2Mi
            requests:
              cpu: 200m
              memory: 1Mi
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
          resources:
            limits:
              cpu: 1000m
              memory: 1Gi
            requests:
              cpu: 100m
              memory: 512Mi
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
        maybe_copy_resources(&DEPLOYMENT, &mut daemonset, &gvk)?;

        let expected = serde_json::json!(ResourceRequirements {
            limits: Some(
                [
                    ("cpu".to_string(), Quantity("1000m".to_string())),
                    ("memory".to_string(), Quantity("1Gi".to_string()))
                ]
                .into()
            ),
            requests: Some(
                [
                    ("cpu".to_string(), Quantity("100m".to_string())),
                    ("memory".to_string(), Quantity("512Mi".to_string()))
                ]
                .into()
            ),
            ..ResourceRequirements::default()
        });
        assert_eq!(
            container(&mut daemonset, "secret-operator")?
                .get("resources")
                .unwrap(),
            &expected
        );
        Ok(())
    }
}
