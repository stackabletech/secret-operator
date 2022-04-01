use std::path::{Path, PathBuf};

use async_trait::async_trait;
use snafu::{ResultExt, Snafu};
use tempfile::tempdir;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use super::pod_info::Address;
use super::{SecretBackend, SecretBackendError};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to create temp dir"))]
    TempSetup { source: std::io::Error },
    #[snafu(display("failed to write Kerberos configuration"))]
    WriteConfig { source: std::io::Error },
    #[snafu(display("failed to spawn kadmin"))]
    SpawnKadmin { source: std::io::Error },
    #[snafu(display("kadmin failed to add principal to keytab, with status {status} and message {keytab_add_msg:?} (additionally, got message {add_principal_msg:?} when creating principal)"))]
    AddToKeytab {
        status: std::process::ExitStatus,
        keytab_add_msg: String,
        add_principal_msg: String,
    },
    #[snafu(display("failed to read keytab"))]
    ReadKeytab { source: std::io::Error },
}
impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::TempSetup { .. } => tonic::Code::Unavailable,
            Error::WriteConfig { .. } => tonic::Code::Unavailable,
            Error::SpawnKadmin { .. } => tonic::Code::FailedPrecondition,
            Error::AddToKeytab { .. } => tonic::Code::Unavailable,
            Error::ReadKeytab { .. } => tonic::Code::Unavailable,
        }
    }
}

pub struct KerberosKeytab {}

#[async_trait]
impl SecretBackend for KerberosKeytab {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: super::SecretVolumeSelector,
        pod_info: super::pod_info::PodInfo,
    ) -> Result<super::SecretFiles, Self::Error> {
        // kadm5_randkey_principal_3(server_handle, principal, keepold, n_ks_tuple, ks_tuple, keyblocks, n_keys)
        let tmp = tempdir().context(TempSetupSnafu)?;
        let profile = format!(
            r#"
[libdefaults]
default_realm = CLUSTER.LOCAL
rdns = false
dns_canonicalize_hostnames = false

[realms]
CLUSTER.LOCAL = {{
  kdc = krb5-kdc
  admin_server = krb5-kdc
}}

[domain_realm]
cluster.local = CLUSTER.LOCAL
.cluster.local = CLUSTER.LOCAL
"#
        );
        let profile_file_path = tmp.path().join("krb5.conf");
        let mut profile_file = File::create(&profile_file_path)
            .await
            .context(WriteConfigSnafu)?;
        profile_file
            .write_all(profile.as_bytes())
            .await
            .context(WriteConfigSnafu)?;
        profile_file.flush().await.context(WriteConfigSnafu)?;
        let keytab_file_path = tmp.path().join("keytab");
        for service_name in &selector.kerberos_service_names {
            for scope in &selector.scope {
                for addr in selector.scope_addresses(&pod_info, scope) {
                    if let Address::Dns(hostname) = addr {
                        add_principal_to_keytab(
                            &profile_file_path,
                            "stackable-secret-operator",
                            "/keytab/kt".as_ref(),
                            &format!("{service_name}/{hostname}"),
                            &keytab_file_path,
                        )
                        .await?;
                    }
                }
            }
        }
        let mut keytab_data = Vec::new();
        let mut keytab_file = File::open(keytab_file_path)
            .await
            .context(ReadKeytabSnafu)?;
        keytab_file
            .read_to_end(&mut keytab_data)
            .await
            .context(ReadKeytabSnafu)?;
        Ok([
            (PathBuf::from("keytab"), keytab_data),
            (PathBuf::from("krb5.conf"), profile.into_bytes()),
        ]
        .into())
        // let profile_file_path = profile_file.path().as_os_str().as_bytes();
        // let config_params = krb5::ConfigParams {
        //     default_realm: Some(CString::new("CLUSTER.LOCAL").unwrap()),
        //     admin_server: Some(CString::new("krb5-kdc").unwrap()),
        //     kadmind_port: Some(749),
        // };
        // let mut profile = krb5::Profile::from_path(&CString::new(profile_file_path).unwrap())
        //     .context(ProfileInitSnafu)?;
        // dbg!(profile_file.keep().unwrap());
        // profile
        //     .set(
        //         &[
        //             &CString::new("realms").unwrap(),
        //             &CString::new("CLUSTER.LOCAL").unwrap(),
        //             &CString::new("kdc").unwrap(),
        //         ],
        //         &CString::new("krb5-kdc").unwrap(),
        //     )
        //     .context(ProfileConfigSnafu)?;
        // profile.flush().context(ProfileConfigSnafu)?;
        // let krb = krb5::KrbContext::from_profile(&profile).context(KrbInitSnafu)?;
        // let kadmin = krb5::ServerHandle::new(
        //     &krb,
        //     &CString::new("stackable-secret-operator@CLUSTER.LOCAL").unwrap(),
        //     &krb5::Credential::ServiceKey {
        //         keytab: CString::new("/keytab/kt").unwrap(),
        //         service_name: CString::new("stackable-secret-operator@CLUSTER.LOCAL").unwrap(),
        //     },
        //     &config_params,
        // )
        // .context(KadminInitSnafu)?;
        // todo!()
    }
}

#[tracing::instrument]
async fn add_principal_to_keytab(
    config_path: &Path,
    admin_principal: &str,
    admin_keytab: &Path,
    pod_principal: &str,
    pod_keytab: &Path,
) -> Result<(), Error> {
    let addprinc_output = Command::new("kadmin")
        .args(["-p", admin_principal, "-kt"])
        .arg(admin_keytab)
        .args(["add_principal", "-randkey", pod_principal])
        .env("KRB5_CONFIG", config_path)
        .output()
        .await
        .context(SpawnKadminSnafu)?;
    if !addprinc_output.status.success() {
        // Try to keep going, the principal might already exist
        tracing::info!("failed to create principal, assuming it already exists")
    }
    let ktadd_output = Command::new("kadmin")
        .args(["-p", admin_principal, "-kt"])
        .arg(admin_keytab)
        .args(["ktadd", "-norandkey", "-k"])
        .arg(pod_keytab)
        .arg(pod_principal)
        .env("KRB5_CONFIG", config_path)
        .output()
        .await
        .context(SpawnKadminSnafu)?;
    if !ktadd_output.status.success() {
        return AddToKeytabSnafu {
            status: ktadd_output.status,
            keytab_add_msg: String::from_utf8_lossy(&ktadd_output.stderr),
            add_principal_msg: String::from_utf8_lossy(&addprinc_output.stderr),
        }
        .fail();
    }
    Ok(())
}
