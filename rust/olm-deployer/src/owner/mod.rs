use anyhow::{Context, Result};
use stackable_operator::{
    k8s_openapi::{
        api::{apps::v1::Deployment, rbac::v1::ClusterRole},
        apimachinery::pkg::apis::meta::v1::OwnerReference,
    },
    kube::{
        Resource,
        api::{DynamicObject, ResourceExt},
        discovery::Scope,
    },
};

/// Updates owner references of objects created by this deployer so that when an operator is
/// uninstalled by OLM, all created objects are also removed by Kubernetes garbage collection.
///
/// Namespaced object's owner references are updated in place with the value of `ns_owner`.
///
/// A previous version of this function also updated cluster scoped objects to set the owner
/// reference to `cluster_owner`, but this turned out to be problematic.
pub(super) fn maybe_update_owner(
    target: &mut DynamicObject,
    scope: &Scope,
    ns_owner: &Deployment,
    cluster_owner: &ClusterRole,
) -> Result<()> {
    let owner_ref = owner_ref(scope, ns_owner, cluster_owner)?;
    // 2025-12-12: do not set owner references for cluster scoped objects anymore to prevent them from being
    // deleted upon operator upgrades.
    if scope == &Scope::Namespaced {
        match target.metadata.owner_references {
            Some(ref mut ors) => ors.push(owner_ref),
            None => target.metadata.owner_references = Some(vec![owner_ref]),
        }
    }
    Ok(())
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
    use std::sync::LazyLock;

    use anyhow::Result;
    use serde::Deserialize;
    use stackable_operator::k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;

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
        let mut daemonset = DAEMONSET.clone();
        maybe_update_owner(
            &mut daemonset,
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
        let mut daemonset = DAEMONSET.clone();
        maybe_update_owner(&mut daemonset, &Scope::Cluster, &DEPLOYMENT, &CLUSTER_ROLE)?;

        let expected = None;

        assert_eq!(daemonset.metadata.owner_references, expected);
        Ok(())
    }
}
