use std::path::{Path, PathBuf};

use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::k8s_openapi::api::core::v1::{Secret, SecretReference};
use tempfile::tempdir;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use super::{pod_info::Address, SecretBackend, SecretBackendError, SecretContents};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid secret reference: {secret:?}"))]
    InvalidSecretRef { secret: SecretReference },
    #[snafu(display("failed to load admin keytab {secret:?}"))]
    LoadAdminKeytab {
        source: stackable_operator::error::Error,
        secret: SecretReference,
    },
    #[snafu(display(r#"admin keytab {secret:?} does not contain field "keytab""#))]
    NoAdminKeytabFieldInSecret { secret: SecretReference },
    #[snafu(display("failed to create temp dir"))]
    TempSetup { source: std::io::Error },
    #[snafu(display("failed to write Kerberos configuration"))]
    WriteConfig { source: std::io::Error },
    #[snafu(display("failed to write admin keytab"))]
    WriteAdminKeytab { source: std::io::Error },
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
            Error::InvalidSecretRef { .. } => tonic::Code::FailedPrecondition,
            Error::LoadAdminKeytab { .. } => tonic::Code::FailedPrecondition,
            Error::NoAdminKeytabFieldInSecret { .. } => tonic::Code::FailedPrecondition,
            Error::TempSetup { .. } => tonic::Code::Unavailable,
            Error::WriteConfig { .. } => tonic::Code::Unavailable,
            Error::WriteAdminKeytab { .. } => tonic::Code::Unavailable,
            Error::SpawnKadmin { .. } => tonic::Code::FailedPrecondition,
            Error::AddToKeytab { .. } => tonic::Code::Unavailable,
            Error::ReadKeytab { .. } => tonic::Code::Unavailable,
        }
    }
}

pub struct KerberosProfile {
    pub realm_name: String,
    pub kdc: String,
    pub admin_server: String,
}

pub struct KerberosKeytab {
    profile: KerberosProfile,
    admin_keytab: Vec<u8>,
    admin_principal: String,
}

impl KerberosKeytab {
    pub async fn new_from_k8s_keytab(
        client: &stackable_operator::client::Client,
        profile: KerberosProfile,
        admin_keytab_secret_ref: &SecretReference,
        admin_principal: impl Into<String>,
    ) -> Result<Self, Error> {
        let (keytab_secret_name, keytab_secret_ns) = match admin_keytab_secret_ref {
            SecretReference {
                name: Some(name),
                namespace: Some(ns),
            } => (name, ns),
            _ => {
                return InvalidSecretRefSnafu {
                    secret: admin_keytab_secret_ref.clone(),
                }
                .fail()
            }
        };
        let admin_keytab_secret = client
            .get::<Secret>(keytab_secret_name, keytab_secret_ns)
            .await
            .context(LoadAdminKeytabSnafu {
                secret: admin_keytab_secret_ref.clone(),
            })?;
        let admin_keytab = admin_keytab_secret
            .data
            .unwrap_or_default()
            .remove("keytab")
            .context(NoAdminKeytabFieldInSecretSnafu {
                secret: admin_keytab_secret_ref.clone(),
            })?
            .0;
        Ok(Self {
            profile,
            admin_keytab,
            admin_principal: admin_principal.into(),
        })
    }
}

#[async_trait]
impl SecretBackend for KerberosKeytab {
    type Error = Error;

    async fn get_secret_data(
        &self,
        selector: &super::SecretVolumeSelector,
        pod_info: super::pod_info::PodInfo,
    ) -> Result<super::SecretContents, Self::Error> {
        let Self {
            profile:
                KerberosProfile {
                    realm_name,
                    kdc,
                    admin_server,
                },
            admin_keytab,
            admin_principal,
        } = self;

        let tmp = tempdir().context(TempSetupSnafu)?;
        let profile = format!(
            r#"
[libdefaults]
default_realm = {realm_name}
rdns = false
dns_canonicalize_hostnames = false

[realms]
{realm_name} = {{
  kdc = {kdc}
  admin_server = {admin_server}
}}

[domain_realm]
cluster.local = {realm_name}
.cluster.local = {realm_name}
"#
        );
        let profile_file_path = tmp.path().join("krb5.conf");
        {
            let mut profile_file = File::create(&profile_file_path)
                .await
                .context(WriteConfigSnafu)?;
            profile_file
                .write_all(profile.as_bytes())
                .await
                .context(WriteConfigSnafu)?;
        }
        let admin_keytab_file_path = tmp.path().join("admin-keytab");
        {
            let mut admin_keytab_file = File::create(&admin_keytab_file_path)
                .await
                .context(WriteAdminKeytabSnafu)?;
            admin_keytab_file
                .write_all(admin_keytab)
                .await
                .context(WriteAdminKeytabSnafu)?;
        }
        let keytab_file_path = tmp.path().join("pod-keytab");
        for service_name in &selector.kerberos_service_names {
            for scope in &selector.scope {
                for addr in selector.scope_addresses(&pod_info, scope) {
                    if let Address::Dns(hostname) = addr {
                        add_principal_to_keytab(
                            &profile_file_path,
                            admin_principal,
                            &admin_keytab_file_path,
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
        Ok(SecretContents::new(
            [
                (PathBuf::from("keytab"), keytab_data),
                (PathBuf::from("krb5.conf"), profile.into_bytes()),
            ]
            .into(),
        ))
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
        // Principal may already be mounted into other pods, so do not regenerate the key
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
