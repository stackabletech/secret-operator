use anyhow::{bail, Result};
use serde_json::{json, Value};
use stackable_operator::kube::api::DynamicObject;

pub(super) fn maybe_patch_namespace(ns: &str, res: &mut DynamicObject) -> Result<()> {
    if let Some(auto_tls) = res.data.pointer_mut("/spec/backend/autoTls") {
        *get_or_insert_default_object(
            get_or_insert_default_object(get_or_insert_default_object(auto_tls, "ca")?, "secret")?,
            "namespace",
        )? = json!(ns.to_string());
    }
    Ok(())
}

fn get_or_insert_default_object<'a>(
    value: &'a mut serde_json::Value,
    key: &str,
) -> Result<&'a mut Value> {
    let map = match value {
        serde_json::Value::Object(map) => map,
        x @ serde_json::Value::Null => {
            *x = json!({});
            x.as_object_mut().unwrap()
        }
        x => {
            bail!("invalid type {x:?}, expected map");
        }
    };
    Ok(map.entry(key).or_insert_with(|| serde_json::Value::Null))
}
