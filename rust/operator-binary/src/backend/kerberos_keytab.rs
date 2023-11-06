use async_trait::async_trait;
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_krb5_provision_keytab::provision_keytab;
use stackable_operator::k8s_openapi::api::core::v1::{Secret, SecretReference};
use tempfile::tempdir;
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
};

use crate::{
    crd::{Hostname, InvalidKerberosPrincipal, KerberosKeytabBackendAdmin, KerberosPrincipal},
    format::{well_known, SecretData, WellKnownSecretData},
};

use super::{
    pod_info::Address, scope::SecretScope, ScopeAddressesError, SecretBackend, SecretBackendError,
    SecretContents,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("invalid secret reference: {secret:?}"))]
    InvalidSecretRef { secret: SecretReference },
    #[snafu(display("failed to get addresses for scope {scope}"))]
    ScopeAddresses {
        source: ScopeAddressesError,
        scope: SecretScope,
    },
    #[snafu(display("failed to load admin keytab {secret:?}"))]
    LoadAdminKeytab {
        source: stackable_operator::error::Error,
        secret: SecretReference,
    },
    #[snafu(display(r#"admin keytab {secret:?} does not contain key "keytab""#))]
    NoAdminKeytabKeyInSecret { secret: SecretReference },
    #[snafu(display("failed to create temp dir"))]
    TempSetup { source: std::io::Error },
    #[snafu(display("failed to write Kerberos configuration"))]
    WriteConfig { source: std::io::Error },
    #[snafu(display("failed to write admin keytab"))]
    WriteAdminKeytab { source: std::io::Error },
    #[snafu(display("failed to provision keytab"))]
    ProvisionKeytab {
        source: stackable_krb5_provision_keytab::Error,
    },
    #[snafu(display("generated invalid Kerberos principal for pod"))]
    PodPrincipal { source: InvalidKerberosPrincipal },
    #[snafu(display("failed to read keytab"))]
    ReadKeytab { source: std::io::Error },
}
impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Error::InvalidSecretRef { .. } => tonic::Code::FailedPrecondition,
            Error::LoadAdminKeytab { .. } => tonic::Code::FailedPrecondition,
            Error::NoAdminKeytabKeyInSecret { .. } => tonic::Code::FailedPrecondition,
            Error::TempSetup { .. } => tonic::Code::Unavailable,
            Error::WriteConfig { .. } => tonic::Code::Unavailable,
            Error::WriteAdminKeytab { .. } => tonic::Code::Unavailable,
            Error::ProvisionKeytab { .. } => tonic::Code::Unavailable,
            Error::PodPrincipal { .. } => tonic::Code::FailedPrecondition,
            Error::ReadKeytab { .. } => tonic::Code::Unavailable,
            Error::ScopeAddresses { .. } => tonic::Code::Unavailable,
        }
    }
}

pub struct KerberosProfile {
    pub realm_name: Hostname,
    pub kdc: Hostname,
    pub admin: KerberosKeytabBackendAdmin,
}

pub struct KerberosKeytab {
    profile: KerberosProfile,
    admin_keytab: Vec<u8>,
    admin_principal: KerberosPrincipal,
}

impl KerberosKeytab {
    pub async fn new_from_k8s_keytab(
        client: &stackable_operator::client::Client,
        profile: KerberosProfile,
        admin_keytab_secret_ref: &SecretReference,
        admin_principal: KerberosPrincipal,
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
            .context(NoAdminKeytabKeyInSecretSnafu {
                secret: admin_keytab_secret_ref.clone(),
            })?
            .0;
        Ok(Self {
            profile,
            admin_keytab,
            admin_principal,
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
                    admin,
                },
            admin_keytab,
            admin_principal,
        } = self;

        let admin_server_clause = match admin {
            KerberosKeytabBackendAdmin::Mit { kadmin_server } => {
                format!("  admin_server = {kadmin_server}")
            }
            KerberosKeytabBackendAdmin::ActiveDirectory { .. } => String::new(),
        };

        let tmp = tempdir().context(TempSetupSnafu)?;
        let profile = format!(
            r#"
[libdefaults]
default_realm = {realm_name}
rdns = false
dns_canonicalize_hostnames = false
udp_preference_limit = 1

[realms]
{realm_name} = {{
  kdc = {kdc}
{admin_server_clause}
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
        let mut pod_principals: Vec<KerberosPrincipal> = Vec::new();
        for service_name in &selector.kerberos_service_names {
            for scope in &selector.scope {
                for addr in
                    selector
                        .scope_addresses(&pod_info, scope)
                        .context(ScopeAddressesSnafu {
                            scope: scope.clone(),
                        })?
                {
                    if let Address::Dns(hostname) = addr {
                        pod_principals.push(
                            format!("{service_name}/{hostname}")
                                .try_into()
                                .context(PodPrincipalSnafu)?,
                        );
                    }
                }
            }
        }
        provision_keytab(
            &profile_file_path,
            &stackable_krb5_provision_keytab::Request {
                admin_keytab_path: admin_keytab_file_path,
                admin_principal_name: admin_principal.to_string(),
                pod_keytab_path: keytab_file_path.clone(),
                principals: pod_principals
                    .into_iter()
                    .map(|princ| stackable_krb5_provision_keytab::PrincipalRequest {
                        name: princ.to_string(),
                    })
                    .collect(),
                admin_backend: match admin {
                    KerberosKeytabBackendAdmin::Mit { .. } => {
                        stackable_krb5_provision_keytab::AdminBackend::Mit
                    }
                    KerberosKeytabBackendAdmin::ActiveDirectory {
                        ldap_server,
                        ldap_tls_ca_secret,
                        password_cache_secret,
                        user_distinguished_name,
                        schema_distinguished_name,
                    } => stackable_krb5_provision_keytab::AdminBackend::ActiveDirectory {
                        ldap_server: ldap_server.to_string(),
                        ldap_tls_ca_secret: ldap_tls_ca_secret.clone(),
                        password_cache_secret: password_cache_secret.clone(),
                        user_distinguished_name: user_distinguished_name.clone(),
                        schema_distinguished_name: schema_distinguished_name.clone(),
                    },
                },
            },
        )
        .await
        .context(ProvisionKeytabSnafu)?;
        let mut keytab_data = Vec::new();
        let mut keytab_file = File::open(keytab_file_path)
            .await
            .context(ReadKeytabSnafu)?;
        keytab_file
            .read_to_end(&mut keytab_data)
            .await
            .context(ReadKeytabSnafu)?;
        Ok(SecretContents::new(SecretData::WellKnown(
            WellKnownSecretData::Kerberos(well_known::Kerberos {
                keytab: keytab_data,
                krb5_conf: profile.into_bytes(),
            }),
        )))
    }
}
