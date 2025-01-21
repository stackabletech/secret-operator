use stackable_operator::k8s_openapi::api::apps::v1::Deployment;
use stackable_operator::k8s_openapi::api::core::v1::Toleration;
use stackable_operator::kube::api::{DynamicObject, GroupVersionKind};

use crate::data::get_or_create;

/// Copies the pod tolerations from the `source` to the `target`.
/// Does nothing if there are no tolerations or if the `target` is not
/// a DaemonSet.
pub(super) fn maybe_copy_tolerations(
    source: &Deployment,
    target: &mut DynamicObject,
    target_gvk: &GroupVersionKind,
) -> anyhow::Result<()> {
    if target_gvk.kind == "DaemonSet" {
        if let Some(tolerations) = deployment_tolerations(source) {
            let path = "template/spec/tolerations".split("/");
            *get_or_create(target.data.pointer_mut("/spec").unwrap(), path)? =
                serde_json::json!(tolerations
                    .iter()
                    .map(|t| serde_json::json!(t))
                    .collect::<Vec<serde_json::Value>>());
        }
    }

    Ok(())
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

    use crate::tolerations::{deployment_tolerations, maybe_copy_tolerations};
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

    #[test]
    fn test_copy_tolerations() -> Result<()> {
        let gvk: GroupVersionKind = GroupVersionKind {
            kind: "DaemonSet".to_string(),
            version: "v1".to_string(),
            group: "apps".to_string(),
        };

        let mut daemonset = DAEMONSET.clone();
        maybe_copy_tolerations(&DEPLOYMENT, &mut daemonset, &gvk)?;

        let expected = serde_json::json!(deployment_tolerations(&DEPLOYMENT)
            .unwrap()
            .iter()
            .map(|t| serde_json::json!(t))
            .collect::<Vec<serde_json::Value>>());

        assert_eq!(
            daemonset.data.pointer("/spec/template/spec/tolerations"),
            Some(&expected)
        );
        Ok(())
    }
}
