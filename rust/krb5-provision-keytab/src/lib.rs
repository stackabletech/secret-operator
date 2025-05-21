//! API wrapper for accessing krb5-provision-keytab binary

use std::{
    path::{Path, PathBuf},
    process::Stdio,
};

use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_secret_operator_crd_utils::SecretReference;
use tokio::{io::AsyncWriteExt, process::Command};

#[derive(Serialize, Deserialize)]
pub struct Request {
    pub admin_keytab_path: PathBuf,
    pub admin_principal_name: String,
    pub pod_keytab_path: PathBuf,
    pub principals: Vec<PrincipalRequest>,
    pub admin_backend: AdminBackend,
}
#[derive(Serialize, Deserialize)]
pub struct PrincipalRequest {
    pub name: String,
}
#[derive(Serialize, Deserialize)]
pub enum AdminBackend {
    Mit,
    ActiveDirectory {
        ldap_server: String,
        ldap_tls_ca_secret: SecretReference,
        password_cache_secret: SecretReference,
        user_distinguished_name: String,
        schema_distinguished_name: String,
        generate_sam_account_name: Option<ActiveDirectorySamAccountNameRules>,
    },
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ActiveDirectorySamAccountNameRules {
    pub prefix: String,
    pub total_length: u8,
}

#[derive(Serialize, Deserialize)]
pub struct Response {}

#[derive(Snafu, Debug)]
pub enum Error {
    #[snafu(display("failed to serialize request"))]
    SerializeRequest { source: serde_json::Error },

    #[snafu(display("failed to deserialize response"))]
    DeserializeResponse { source: serde_json::Error },

    #[snafu(display("failed to start provisioner"))]
    SpawnProvisioner { source: std::io::Error },

    #[snafu(display("error waiting for provisioner to exit"))]
    WaitProvisioner { source: std::io::Error },

    #[snafu(display("failed to provision keytab: {msg}"))]
    RunProvisioner { msg: String },

    #[snafu(display("failed to write request"))]
    WriteRequest { source: std::io::Error },

    #[snafu(display("failed to obtain stdin for child process"))]
    ChildStdin,
}

/// Provisions a Kerberos Keytab based on the [`Request`].
///
/// This function assumes that the binary produced by this crate is on the `$PATH`, and will fail otherwise.
pub async fn provision_keytab(krb5_config_path: &Path, req: &Request) -> Result<Response, Error> {
    let req_str = serde_json::to_vec(&req).context(SerializeRequestSnafu)?;

    let mut child = Command::new("stackable-krb5-provision-keytab")
        // make sure the process is killed if we error out of this fn somewhere due to
        // an error when writing to stdin or getting stdout
        // Usually we'd expect the process to terminate on its own, this is a fail safe to ensure
        // it gets killed in case it hangs for some reason.
        .kill_on_drop(true)
        .env("KRB5_CONFIG", krb5_config_path)
        // ldap3 uses the default client keytab to authenticate to the LDAP server
        .env("KRB5_CLIENT_KTNAME", &req.admin_keytab_path)
        // avoid leaking credentials between secret volumes/secretclasses by only storing the
        // TGT that is obtained for the operation in the memory of the short lives process
        // spawned by `Command::new` above - this way it'll be wiped from memory once this exits
        // With any shared or persistent ticket cache this might stick around and potentially be
        // reused by later runs
        .env("KRB5CCNAME", "MEMORY:")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context(SpawnProvisionerSnafu)?;

    // Get a `ChildStdin` object for the spawned process and write the serialized request
    // for a Principal into it in order for the child process to deserialize it and
    // process the request
    let mut stdin = child.stdin.take().context(ChildStdinSnafu)?;
    stdin.write_all(&req_str).await.context(WriteRequestSnafu)?;
    stdin.flush().await.context(WriteRequestSnafu)?;
    drop(stdin);

    // Wait for the process to finish and capture output
    // This will always return Ok(...) regardless of exit code or output of the child process
    // Failure here means that something went wrong with connecting to the process or obtaining
    // exit code or output
    let output = child
        .wait_with_output()
        .await
        .context(WaitProvisionerSnafu)?;

    // Check for success of the operation by deserializing stdout of the process to a `Response`
    // struct - since `Response` is an empty struct with no fields this effectively means that
    // any output will fail to deserialize and cause an `Error::RunProvisioner` to be propagated
    // with the output of the child process
    serde_json::from_slice::<Result<Response, String>>(&output.stdout)
        .context(DeserializeResponseSnafu)?
        .map_err(|msg| Error::RunProvisioner { msg })
}
