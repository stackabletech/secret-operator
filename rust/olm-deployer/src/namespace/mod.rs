use anyhow::Result;
use serde_json::{Value, json};
use stackable_operator::kube::api::{DynamicObject, GroupVersionKind};

use crate::data;

/// Path the namespace of the autoTls secret class.
/// Otherwise do nothing.
pub(super) fn maybe_patch_namespace(
    ns: &str,
    res: &mut DynamicObject,
    gvk: &GroupVersionKind,
) -> Result<()> {
    if gvk.kind == "SecretClass" {
        *auto_tls_namespace(&mut res.data)? = json!(ns.to_string());
    }
    Ok(())
}

fn auto_tls_namespace(value: &mut serde_json::Value) -> Result<&mut Value> {
    data::data_field_as_mut(value, "/spec/backend/autoTls/ca/secret/namespace")
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use anyhow::Result;
    use serde::Deserialize;

    use super::*;

    static TLS_SECRET_CLASS: LazyLock<DynamicObject> = LazyLock::new(|| {
        const STR_TLS_SECRET_CLASS: &str = r#"
---
apiVersion: secrets.stackable.tech/v1alpha1
kind: SecretClass
metadata:
  name: tls
  labels:
    app.kubernetes.io/name: secret-operator
    app.kubernetes.io/instance: secret-operator
    stackable.tech/vendor: Stackable
    app.kubernetes.io/version: "24.11.0"
spec:
  backend:
    autoTls:
      ca:
        secret:
          name: secret-provisioner-tls-ca
          namespace: "${NAMESPACE}" # TODO patch with olm-deployer
        autoGenerate: true
"#;

        let data = serde_yaml::Value::deserialize(serde_yaml::Deserializer::from_str(
            STR_TLS_SECRET_CLASS,
        ))
        .unwrap();
        serde_yaml::from_value(data).unwrap()
    });

    #[test]
    fn test_patch_namespace() -> Result<()> {
        let gvk: GroupVersionKind = GroupVersionKind {
            kind: "SecretClass".to_string(),
            version: "v1alpha1".to_string(),
            group: "secrets.stackable.tech".to_string(),
        };
        let mut tls = TLS_SECRET_CLASS.clone();
        maybe_patch_namespace("prod", &mut tls, &gvk)?;

        let expected = json!("prod");
        assert_eq!(auto_tls_namespace(&mut tls.data)?, &expected);
        Ok(())
    }
}
