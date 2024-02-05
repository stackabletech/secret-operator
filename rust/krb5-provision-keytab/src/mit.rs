use std::ffi::CStr;

use krb5::{kadm5, Keytab, Principal};
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to initialize kadm5 server handle"))]
    KadminInit { source: kadm5::Error },

    #[snafu(display("failed to create principal"))]
    CreatePrincipal { source: kadm5::Error },

    #[snafu(display("failed to principal's keys"))]
    GetPrincipalKeys { source: kadm5::Error },

    #[snafu(display("failed to add key to keytab"))]
    AddToKeytab { source: krb5::Error },
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct MitAdmin<'a> {
    kadmin: kadm5::ServerHandle<'a>,
}
impl<'a> MitAdmin<'a> {
    pub fn connect(
        krb: &'a krb5::KrbContext,
        admin_principal_name: &CStr,
        admin_keytab_path: &CStr,
    ) -> Result<Self> {
        Ok(Self {
            kadmin: kadm5::ServerHandle::new(
                krb,
                admin_principal_name,
                None,
                &krb5::kadm5::Credential::ServiceKey {
                    keytab: admin_keytab_path.to_owned(),
                },
                &kadm5::ConfigParams::default(),
            )
            .context(KadminInitSnafu)?,
        })
    }

    #[tracing::instrument(skip(self, principal, kt), fields(principal = %principal))]
    pub fn create_and_add_principal_to_keytab(
        &self,
        principal: &Principal,
        kt: &mut Keytab,
    ) -> Result<()> {
        tracing::info!("creating principal");
        match self.kadmin.create_principal(principal) {
            Err(kadm5::Error { code, .. }) if code.0 == kadm5::error_code::DUP => {
                tracing::info!("principal already exists, reusing")
            }
            res => res.context(CreatePrincipalSnafu)?,
        }
        let keys = self
            .kadmin
            .get_principal_keys(principal, kadm5::KVNO_ALL)
            .context(GetPrincipalKeysSnafu)?;
        for key in keys.keys() {
            kt.add(principal, key.kvno, &key.keyblock)
                .context(AddToKeytabSnafu)?;
        }
        Ok(())
    }
}
