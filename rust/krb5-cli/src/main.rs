use std::{
    ffi::CString,
    io::{stdin, BufReader},
};

use krb5::{
    kadm5::{self, KadmError},
    Keytab,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct Request {
    admin_keytab_path: String,
    admin_principal_name: String,
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
    // let profile_file = NamedTempFile::new()?;
    // let profile_file_path = profile_file.path().as_os_str().as_bytes();
    // // let profile_file_path = "krb.conf";

    // let config_params = krb5::ConfigParams {
    //     default_realm: Some(CString::new("CLUSTER.LOCAL").unwrap()),
    //     admin_server: Some(CString::new("localhost").unwrap()),
    //     kadmind_port: Some(749),
    // };
    // let mut profile = krb5::Profile::from_path(&CString::new(profile_file_path).unwrap())?;
    // profile.set(
    //     &[
    //         &CString::new("realms").unwrap(),
    //         &CString::new("CLUSTER.LOCAL").unwrap(),
    //         &CString::new("kdc").unwrap(),
    //     ],
    //     &CString::new("localhost").unwrap(),
    // )?;
    // profile.flush()?;
    // let krb = krb5::KrbContext::from_profile(&profile)?;
    let config_params = krb5::kadm5::ConfigParams::default();
    // let config_params = krb5::ConfigParams {
    //     default_realm: Some(CString::new("CLUSTER.LOCAL").unwrap()),
    //     admin_server: Some(CString::new("krb5-kdc").unwrap()),
    //     kadmind_port: Some(749),
    // };
    println!("initing context");
    let krb = krb5::KrbContext::new_kadm5()?;
    let admin_principal_name = CString::new(req.admin_principal_name).unwrap();
    let admin_keytab_path = CString::new(req.admin_keytab_path).unwrap();
    println!("initing kadmin");
    let kadmin = krb5::kadm5::ServerHandle::new(
        &krb,
        &admin_principal_name,
        None,
        // service_name: admin_principal_name.clone(),
        &krb5::kadm5::Credential::ServiceKey {
            keytab: admin_keytab_path,
        },
        &config_params,
    )?;
    let mut kt = Keytab::resolve(&krb, &CString::new("/new-kt").unwrap())?;
    for princ_req in req.principals {
        let princ = krb.parse_name(&princ_req.name)?;
        match kadmin.create_principal(&princ) {
            Err(KadmError { code, .. }) if code.0 == kadm5::error_code::DUP => {
                println!("principal already exists, reusing")
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
