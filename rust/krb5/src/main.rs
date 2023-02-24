use std::{ffi::CString, os::unix::prelude::OsStrExt};

use tempfile::NamedTempFile;

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let profile_file = NamedTempFile::new()?;
    let profile_file_path = profile_file.path().as_os_str().as_bytes();
    // let profile_file_path = "krb.conf";

    let config_params = krb5::kadm5::ConfigParams {
        default_realm: Some(CString::new("CLUSTER.LOCAL").unwrap()),
        admin_server: Some(CString::new("localhost").unwrap()),
        kadmind_port: Some(749),
    };
    let mut profile = krb5::profile::Profile::from_path(&CString::new(profile_file_path).unwrap())?;
    profile.set(
        &[
            &CString::new("realms").unwrap(),
            &CString::new("CLUSTER.LOCAL").unwrap(),
            &CString::new("kdc").unwrap(),
        ],
        &CString::new("localhost").unwrap(),
    )?;
    profile.flush()?;
    let krb = krb5::KrbContext::from_profile(&profile)?;
    let kadmin = krb5::kadm5::ServerHandle::new(
        &krb,
        &CString::new("stackable-secret-operator@CLUSTER.LOCAL").unwrap(),
        None,
        &krb5::kadm5::Credential::ServiceKey {
            keytab: CString::new("kt").unwrap(),
            // keytab: CString::new("/keytab/kt").unwrap(),
        },
        &config_params,
    )?;
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
    {}
}
