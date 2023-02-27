use std::{
    ffi::CString,
    io::{stdin, BufReader},
};

use krb5::{kadm5, Keytab};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    admin_keytab_path: String,
    admin_principal_name: String,
    pod_keytab_path: String,
    principals: Vec<PrincipalRequest>,
}
#[derive(Deserialize)]
struct PrincipalRequest {
    name: CString,
}

#[derive(Serialize)]
struct Response {
    keytab: Vec<u8>,
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let req = serde_json::from_reader::<_, Request>(BufReader::new(stdin().lock())).unwrap();
    let config_params = krb5::kadm5::ConfigParams::default();
    eprintln!("initing context");
    let krb = krb5::KrbContext::new_kadm5()?;
    let admin_principal_name = CString::new(req.admin_principal_name).unwrap();
    let admin_keytab_path = CString::new(req.admin_keytab_path).unwrap();
    eprintln!("initing kadmin");
    let kadmin = krb5::kadm5::ServerHandle::new(
        &krb,
        &admin_principal_name,
        None,
        &krb5::kadm5::Credential::ServiceKey {
            keytab: admin_keytab_path,
        },
        &config_params,
    )?;
    let mut kt = Keytab::resolve(&krb, &CString::new(req.pod_keytab_path).unwrap())?;
    for princ_req in req.principals {
        let princ = krb.parse_name(&princ_req.name)?;
        match kadmin.create_principal(&princ) {
            Err(kadm5::Error { code, .. }) if code.0 == kadm5::error_code::DUP => {
                eprintln!("principal {princ} already exists, reusing")
            }
            res => res?,
        }
        let keys = kadmin.get_principal_keys(&princ, 1)?;
        for key in keys.keys() {
            kt.add(&princ, key.kvno, &key.keyblock)?;
        }
    }
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
