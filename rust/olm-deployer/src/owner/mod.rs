use anyhow::{Context, Result};
use stackable_operator::k8s_openapi::api::apps::v1::Deployment;
use stackable_operator::k8s_openapi::api::rbac::v1::ClusterRole;
use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use stackable_operator::kube::api::DynamicObject;
use stackable_operator::kube::api::ResourceExt;
use stackable_operator::kube::discovery::Scope;
use stackable_operator::kube::Resource;

pub fn maybe_update_owner(
    dynamic_object: DynamicObject,
    scope: &Scope,
    deployment: &Deployment,
    cluster_role: &ClusterRole,
) -> Result<DynamicObject> {
    // TODO: skip SecurityContextConstraints ?
    let owner_ref = owner_ref(scope, deployment, cluster_role)?;
    let mut ret = dynamic_object.clone();
    match ret.metadata.owner_references {
        Some(ref mut ors) => ors.push(owner_ref),
        None => ret.metadata.owner_references = Some(vec![owner_ref]),
    }
    Ok(ret)
}

fn owner_ref(scope: &Scope, depl: &Deployment, cr: &ClusterRole) -> Result<OwnerReference> {
    match scope {
        Scope::Cluster => cr.owner_ref(&()).context(format!(
            "Cannot make owner ref from ClusterRole [{}]",
            cr.name_any()
        )),
        Scope::Namespaced => depl.owner_ref(&()).context(format!(
            "Cannot make owner ref from Deployment [{}]",
            depl.name_any()
        )),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;
    use serde::Deserialize;
    use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

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
}
