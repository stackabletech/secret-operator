use std::{
    ffi::{CString, NulError},
    fmt::Display,
    io::{stdin, BufReader},
};

use krb5::{kadm5, Keyblock, Keytab};
use snafu::{ResultExt, Snafu};
use stackable_krb5_provision_keytab::{AdminBackend, Request, Response};
use tracing::info;

mod active_directory;
mod credential_cache;
mod mit;

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("failed to deserialize request"))]
    DeserializeRequest { source: serde_json::Error },

    #[snafu(display("failed to init krb5 context"))]
    KrbInit { source: krb5::Error },

    #[snafu(display("failed to init MIT admin client"))]
    MitAdminInit { source: mit::Error },

    #[snafu(display("failed to init Active Directory admin client"))]
    ActiveDirectoryInit { source: active_directory::Error },

    #[snafu(display("failed to init kadmin server handle"))]
    KadminInit { source: kadm5::Error },

    #[snafu(display("failed to decode admin principal name"))]
    DecodeAdminPrincipalName { source: NulError },

    #[snafu(display("failed to decode pod principal name"))]
    DecodePodPrincipalName { source: NulError },

    #[snafu(display("failed to decode admin keytab path"))]
    DecodeAdminKeytabPath { source: NulError },

    #[snafu(display("failed to decode pod keytab path"))]
    DecodePodKeytabPath { source: NulError },

    #[snafu(display("failed to resolve pod keytab"))]
    ResolvePodKeytab { source: krb5::Error },

    #[snafu(display("failed to parse principal {principal:?}"))]
    ParsePrincipal {
        source: krb5::Error,
        principal: String,
    },

    #[snafu(display("failed to prepare principal {principal} (backend: MIT)"))]
    PreparePrincipalMit {
        source: mit::Error,
        principal: String,
    },

    #[snafu(display("failed to prepare principal {principal} (backend: Active Directory)"))]
    PreparePrincipalActiveDirectory {
        source: active_directory::Error,
        principal: String,
    },

    #[snafu(display("failed to create principal {principal}"))]
    CreatePrincipal {
        source: kadm5::Error,
        principal: String,
    },

    #[snafu(display("failed to add dummy key to keytab"))]
    AddDummyToKeytab { source: krb5::Error },

    #[snafu(display("failed to remove dummy key from keytab"))]
    RemoveDummyFromKeytab { source: krb5::Error },
}

enum AdminConnection<'a> {
    Mit(mit::MitAdmin<'a>),
    ActiveDirectory(active_directory::AdAdmin<'a>),
}

async fn run() -> Result<Response, Error> {
    let req = serde_json::from_reader::<_, Request>(BufReader::new(stdin().lock()))
        .context(DeserializeRequestSnafu)?;
    info!("initing context");
    let krb = krb5::KrbContext::new().context(KrbInitSnafu)?;
    let admin_principal_name =
        CString::new(req.admin_principal_name).context(DecodeAdminPrincipalNameSnafu)?;
    let admin_keytab_path = CString::new(&*req.admin_keytab_path.as_os_str().to_string_lossy())
        .context(DecodeAdminKeytabPathSnafu)?;
    info!("initing kadmin");

    let mut admin = match req.admin_backend {
        AdminBackend::Mit => AdminConnection::Mit(
            mit::MitAdmin::connect(&krb, &admin_principal_name, &admin_keytab_path)
                .context(MitAdminInitSnafu)?,
        ),
        AdminBackend::ActiveDirectory {
            ldap_server,
            ldap_tls_ca_secret,
            password_cache_secret,
            user_distinguished_name,
            schema_distinguished_name,
        } => AdminConnection::ActiveDirectory(
            active_directory::AdAdmin::connect(
                &ldap_server,
                &krb,
                ldap_tls_ca_secret,
                password_cache_secret,
                user_distinguished_name,
                schema_distinguished_name,
            )
            .await
            .context(ActiveDirectoryInitSnafu)?,
        ),
    };
    let mut kt = Keytab::resolve(
        &krb,
        &CString::new(&*req.pod_keytab_path.as_os_str().to_string_lossy())
            .context(DecodePodKeytabPathSnafu)?,
    )
    .context(ResolvePodKeytabSnafu)?;

    // Insert an invalid dummy principal to ensure that the Keytab is always created, even if no principals are provisioned
    let dummy_principal_name = "_dummy_principal@MISSING.REALM";
    let dummy_principal = krb
        .parse_principal_name(
            &CString::new(dummy_principal_name).expect("dummy principal name must be valid"),
        )
        .context(ParsePrincipalSnafu {
            principal: dummy_principal_name,
        })?;
    let dummy_kvno = 0;
    kt.add(
        &dummy_principal,
        dummy_kvno,
        // keyblock len must be >0, or kt.add() will always fail
        &Keyblock::new(&krb, 0, 1)
            .context(AddDummyToKeytabSnafu)?
            .as_ref(),
    )
    .context(AddDummyToKeytabSnafu)?;
    // Remove dummy key once we have forced the keytab to be created,
    // to avoid tools trying to use it to authenticate
    kt.remove(&dummy_principal, dummy_kvno)
        .context(RemoveDummyFromKeytabSnafu)?;

    for princ_req in req.principals {
        let princ = krb
            .parse_principal_name(
                &CString::new(princ_req.name.as_str()).context(DecodePodPrincipalNameSnafu)?,
            )
            .context(ParsePrincipalSnafu {
                principal: &princ_req.name,
            })?;
        match &mut admin {
            AdminConnection::Mit(mit) => mit
                .create_and_add_principal_to_keytab(&princ, &mut kt)
                .context(PreparePrincipalMitSnafu { principal: &princ })?,
            AdminConnection::ActiveDirectory(ad) => ad
                .create_and_add_principal_to_keytab(&princ, &mut kt)
                .await
                .context(PreparePrincipalActiveDirectorySnafu { principal: &princ })?,
        }
    }
    Ok(Response {})
}

struct Report<E> {
    error: E,
}
impl<T: std::error::Error> From<T> for Report<T> {
    fn from(error: T) -> Self {
        Self { error }
    }
}
impl<T: std::error::Error> Display for Report<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut is_first = true;
        let mut curr: Option<&(dyn std::error::Error)> = Some(&self.error);
        while let Some(err) = curr {
            if !is_first {
                f.write_str(": ")?;
            }
            is_first = false;
            std::fmt::Display::fmt(&err, f)?;
            curr = err.source();
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let res = run().await.map_err(|err| Report::from(err).to_string());
    println!("{}", serde_json::to_string_pretty(&res).unwrap());
    std::process::exit(res.is_ok().into());
}
