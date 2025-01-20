use stackable_operator::k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use stackable_operator::k8s_openapi::api::core::v1::ResourceRequirements;
use stackable_operator::kube::api::DynamicObject;

pub(super) fn copy_resources(
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
                        let d_res = deployment_resources(deployment);
                        c.resources = d_res;
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

fn deployment_resources(deployment: &Deployment) -> Option<ResourceRequirements> {
    deployment
        .spec
        .as_ref()
        .and_then(|ds| ds.template.spec.as_ref())
        .map(|ts| ts.containers.iter())
        .into_iter()
        .flatten()
        .filter(|c| c.name == "secret-operator-deployer")
        .last()
        .and_then(|c| c.resources.clone())
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
              cpu: 100m
              memory: 512Mi
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
        let daemonset = copy_resources(&DEPLOYMENT, DAEMONSET.clone())?;

        assert_eq!(
            daemonset_resources(&daemonset.try_parse::<DaemonSet>()?),
            deployment_resources(&DEPLOYMENT),
        );
        Ok(())
    }

    fn daemonset_resources(daemonset: &DaemonSet) -> Option<ResourceRequirements> {
        daemonset
            .spec
            .as_ref()
            .and_then(|ds| ds.template.spec.as_ref())
            .map(|ts| ts.containers.iter())
            .into_iter()
            .flatten()
            .filter(|c| c.name == "secret-operator")
            .last()
            .and_then(|c| c.resources.clone())
    }
}
