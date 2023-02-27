use std::{
    ffi::{CString, NulError},
    fmt::Display,
    io::{stdin, BufReader},
};

use krb5::{kadm5, Keytab};
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use tracing::info;

#[derive(Deserialize)]
struct Request {
    admin_keytab_path: String,
    admin_principal_name: String,
    pod_keytab_path: String,
    principals: Vec<PrincipalRequest>,
}
#[derive(Deserialize)]
struct PrincipalRequest {
    name: String,
}

#[derive(Serialize)]
struct Response {}

#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("failed to deserialize request"))]
    DeserializeRequest { source: serde_json::Error },
    #[snafu(display("failed to init krb5 context"))]
    KrbInit { source: krb5::Error },
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
    #[snafu(display("failed to create principal {principal}"))]
    CreatePrincipal {
        source: kadm5::Error,
        principal: String,
    },
    #[snafu(display("failed to get keys for principal {principal}"))]
    GetPrincipalKeys {
        source: kadm5::Error,
        principal: String,
    },
    #[snafu(display("failed to add key to keytab"))]
    AddToKeytab { source: krb5::Error },
}

fn run() -> Result<Response, Error> {
    let req = serde_json::from_reader::<_, Request>(BufReader::new(stdin().lock()))
        .context(DeserializeRequestSnafu)?;
    let config_params = krb5::kadm5::ConfigParams::default();
    info!("initing context");
    let krb = krb5::KrbContext::new().context(KrbInitSnafu)?;
    let admin_principal_name =
        CString::new(req.admin_principal_name).context(DecodeAdminPrincipalNameSnafu)?;
    let admin_keytab_path =
        CString::new(req.admin_keytab_path).context(DecodeAdminKeytabPathSnafu)?;
    info!("initing kadmin");
    let kadmin = krb5::kadm5::ServerHandle::new(
        &krb,
        &admin_principal_name,
        None,
        &krb5::kadm5::Credential::ServiceKey {
            keytab: admin_keytab_path,
        },
        &config_params,
    )
    .context(KadminInitSnafu)?;
    let mut kt = Keytab::resolve(
        &krb,
        &CString::new(req.pod_keytab_path).context(DecodePodKeytabPathSnafu)?,
    )
    .context(ResolvePodKeytabSnafu)?;
    for princ_req in req.principals {
        let princ = krb
            .parse_principal_name(
                &CString::new(princ_req.name.as_str()).context(DecodePodPrincipalNameSnafu)?,
            )
            .context(ParsePrincipalSnafu {
                principal: princ_req.name,
            })?;
        match kadmin.create_principal(&princ) {
            Err(kadm5::Error { code, .. }) if code.0 == kadm5::error_code::DUP => {
                info!("principal {princ} already exists, reusing")
            }
            res => res.context(CreatePrincipalSnafu { principal: &princ })?,
        }
        let keys = kadmin
            .get_principal_keys(&princ, 1)
            .context(GetPrincipalKeysSnafu { principal: &princ })?;
        for key in keys.keys() {
            kt.add(&princ, key.kvno, &key.keyblock)
                .context(AddToKeytabSnafu)?;
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

fn main() {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let res = run().map_err(|err| Report::from(err).to_string());
    println!("{}", serde_json::to_string_pretty(&res).unwrap());
    std::process::exit(res.is_ok().into());
}
