pub mod controller;
pub mod identity;
pub mod node;

/// Logs the error returned by a CSI endpoint, if any.
///
/// CSI errors are otherwise only visible to whoever called us (the Kubelet, or the
/// external-provisioner sidecar), never in our own logs.
fn log_if_endpoint_error<T, E: std::error::Error + 'static>(
    error_msg: &str,
    res: Result<T, E>,
) -> Result<T, E> {
    if let Err(err) = &res {
        tracing::warn!(error = err as &dyn std::error::Error, "{error_msg}");
    }
    res
}
