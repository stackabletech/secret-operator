use anyhow::{bail, Result};

pub fn data_field_as_mut<'a>(
    value: &'a mut serde_json::Value,
    pointer: &str,
) -> Result<&'a mut serde_json::Value> {
    match value.pointer_mut(pointer) {
        Some(field) => Ok(field),
        x => bail!("invalid pointer {pointer} for object {x:?}"),
    }
}
