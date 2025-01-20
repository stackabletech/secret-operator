use stackable_operator::k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use stackable_operator::k8s_openapi::api::core::v1::Toleration;
use stackable_operator::kube::api::DynamicObject;

pub(super) fn maybe_copy_tolerations(
    deployment: &Deployment,
    res: DynamicObject,
) -> anyhow::Result<DynamicObject> {
    let ds: anyhow::Result<DaemonSet, _> = res.clone().try_parse();
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
        let daemonset = maybe_copy_tolerations(&DEPLOYMENT, DAEMONSET.clone())?;

        assert_eq!(
            daemonset_tolerations(&daemonset.try_parse::<DaemonSet>()?),
            deployment_tolerations(&DEPLOYMENT)
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
