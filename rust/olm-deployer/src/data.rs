use anyhow::{Result, bail};
use stackable_operator::kube::{ResourceExt, api::DynamicObject};

pub fn data_field_as_mut<'a>(
    value: &'a mut serde_json::Value,
    pointer: &str,
) -> Result<&'a mut serde_json::Value> {
    match value.pointer_mut(pointer) {
        Some(field) => Ok(field),
        x => bail!("invalid pointer {pointer} for object {x:?}"),
    }
}

pub fn container<'a>(
    target: &'a mut DynamicObject,
    container_name: &str,
) -> anyhow::Result<&'a mut serde_json::Value> {
    let tname = target.name_any();
    let path = "template/spec/containers".split("/");
    match get_or_create(target.data.pointer_mut("/spec").unwrap(), path)? {
        serde_json::Value::Array(containers) => {
            for c in containers {
                if c.is_object() {
                    if let Some(serde_json::Value::String(name)) = c.get("name") {
                        if container_name == name {
                            return Ok(c);
                        }
                    }
                } else {
                    anyhow::bail!("container is not a object: {:?}", c);
                }
            }
            anyhow::bail!("container named {container_name} not found");
        }
        _ => anyhow::bail!("no containers found in object {tname}"),
    }
}

/// Returns the object nested in `root` by traversing the `path` of nested keys.
/// Creates any missing objects in path.
/// In case of success, the returned value is either the existing object or
/// serde_json::Value::Null.
/// Returns an error if any of the nested objects has a type other than map.
pub fn get_or_create<'a, 'b, I>(
    root: &'a mut serde_json::Value,
    path: I,
) -> anyhow::Result<&'a mut serde_json::Value>
where
    I: IntoIterator<Item = &'b str>,
{
    let mut iter = path.into_iter();
    match iter.next() {
        None => Ok(root),
        Some(first) => {
            let new_root = get_or_insert_default_object(root, first)?;
            get_or_create(new_root, iter)
        }
    }
}

/// Given a map object create or return the object corresponding to the given `key`.
fn get_or_insert_default_object<'a>(
    value: &'a mut serde_json::Value,
    key: &str,
) -> anyhow::Result<&'a mut serde_json::Value> {
    let map = match value {
        serde_json::Value::Object(map) => map,
        x @ serde_json::Value::Null => {
            *x = serde_json::json!({});
            x.as_object_mut().unwrap()
        }
        x => anyhow::bail!("invalid type {x:?}, expected map"),
    };
    Ok(map.entry(key).or_insert_with(|| serde_json::Value::Null))
}
