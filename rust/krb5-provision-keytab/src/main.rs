use std::{
    collections::BTreeMap,
    ffi::{CString, NulError},
    fmt::Display,
    io::{stdin, BufReader},
};

use byteorder::{LittleEndian, WriteBytesExt};
use krb5::{
    kadm5::{self, KVNO_ALL},
    Keyblock, Keytab,
};
use ldap3::{LdapConnAsync, LdapConnSettings};
use snafu::{ResultExt, Snafu};
use stackable_krb5_provision_keytab::{AdminBackend, Request, Response};
use stackable_operator::k8s_openapi::{
    api::core::v1::{Secret, SecretReference},
    ByteString,
};
use tracing::info;

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
    #[snafu(display("failed to create dummy key"))]
    CreateDummyKey { source: krb5::Error },
    #[snafu(display("failed to add key for principal {principal} to keytab"))]
    AddToKeytab {
        source: krb5::Error,
        principal: String,
    },
}

enum AdminConnection<'a> {
    Mit {
        kadmin: krb5::kadm5::ServerHandle<'a>,
    },
    ActiveDirectory {
        ldap: ldap3::Ldap,
        password_cache_secret: SecretReference,
    },
}

async fn run() -> Result<Response, Error> {
    let req = serde_json::from_reader::<_, Request>(BufReader::new(stdin().lock()))
        .context(DeserializeRequestSnafu)?;
    let config_params = krb5::kadm5::ConfigParams::default();
    info!("initing context");
    let krb = krb5::KrbContext::new().context(KrbInitSnafu)?;
    let admin_principal_name =
        CString::new(req.admin_principal_name).context(DecodeAdminPrincipalNameSnafu)?;
    let admin_keytab_path = CString::new(&*req.admin_keytab_path.as_os_str().to_string_lossy())
        .context(DecodeAdminKeytabPathSnafu)?;
    info!("initing kadmin");

    let mut admin = match req.admin_backend {
        AdminBackend::Mit => AdminConnection::Mit {
            kadmin: krb5::kadm5::ServerHandle::new(
                &krb,
                &admin_principal_name,
                None,
                &krb5::kadm5::Credential::ServiceKey {
                    keytab: admin_keytab_path,
                },
                &config_params,
            )
            .context(KadminInitSnafu)?,
        },
        AdminBackend::ActiveDirectory {
            ldap_server,
            password_cache_secret,
        } => {
            let (ldap_conn, mut ldap) = LdapConnAsync::with_settings(
                LdapConnSettings::new()
                    // FIXME: This is obviously not a good idea
                    .set_no_tls_verify(true),
                &format!("ldaps://{ldap_server}"),
            )
            .await
            .unwrap();
            ldap3::drive!(ldap_conn);
            ldap.sasl_gssapi_bind(&ldap_server).await.unwrap();
            AdminConnection::ActiveDirectory {
                ldap,
                password_cache_secret,
            }
        }
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
    kt.add(
        &dummy_principal,
        0,
        // keyblock len must be >0, or kt.add() will always fail
        &Keyblock::new(&krb, 0, 1)
            .context(CreateDummyKeySnafu)?
            .as_ref(),
    )
    .context(AddToKeytabSnafu {
        principal: &dummy_principal,
    })?;

    for princ_req in req.principals {
        let princ = krb
            .parse_principal_name(
                &CString::new(princ_req.name.as_str()).context(DecodePodPrincipalNameSnafu)?,
            )
            .context(ParsePrincipalSnafu {
                principal: &princ_req.name,
            })?;
        match &mut admin {
            AdminConnection::Mit { kadmin } => {
                match kadmin.create_principal(&princ) {
                    Err(kadm5::Error { code, .. }) if code.0 == kadm5::error_code::DUP => {
                        info!("principal {princ} already exists, reusing")
                    }
                    res => res.context(CreatePrincipalSnafu { principal: &princ })?,
                }
                let keys = kadmin
                    .get_principal_keys(&princ, KVNO_ALL)
                    .context(GetPrincipalKeysSnafu { principal: &princ })?;
                for key in keys.keys() {
                    kt.add(&princ, key.kvno, &key.keyblock)
                        .context(AddToKeytabSnafu { principal: &princ })?;
                }
            }
            AdminConnection::ActiveDirectory {
                ldap,
                password_cache_secret,
            } => {
                let kube = stackable_operator::client::create_client(None)
                    .await
                    .unwrap();
                let mut password_cache = kube
                    .get::<Secret>(
                        password_cache_secret.name.as_deref().unwrap(),
                        password_cache_secret.namespace.as_deref().unwrap(),
                    )
                    .await
                    .unwrap();
                let password_cache_key = princ_req.name.replace(['/', '@'], "--");
                let password = if let Some(pw) = password_cache
                    .data
                    .get_or_insert_with(BTreeMap::default)
                    .get(&password_cache_key)
                {
                    tracing::info!(
                        principal = princ_req.name,
                        cache_key = password_cache_key,
                        "found principal in key cache, reusing"
                    );
                    pw.0.clone()
                } else {
                    tracing::info!(
                        principal = princ_req.name,
                        cache_key = password_cache_key,
                        "did not find principal in key cache, creating"
                    );
                    let realm_name = krb.default_realm().unwrap();
                    let realm_name = realm_name.to_string_lossy();
                    let realm_dn = realm_name
                        .split('.')
                        .map(|part| format!("DC={part}"))
                        .collect::<Vec<_>>()
                        .join(",");
                    tracing::info!(principal = ?princ_req.name, "Creating principal");
                    let principal_cn = ldap3::dn_escape(&*princ_req.name);
                    let password = "asdfasdf";
                    let password_ad_encoded = {
                        let mut pwd_utf16le = Vec::new();
                        format!("\"{password}\"").encode_utf16().for_each(|word| {
                            WriteBytesExt::write_u16::<LittleEndian>(&mut pwd_utf16le, word)
                                .unwrap()
                        });
                        pwd_utf16le
                    };
                    // FIXME: AD restricts RDNs to 64 characters
                    let principal_cn = principal_cn.get(..64).unwrap_or(&*principal_cn);
                    let user_dn = format!("CN={principal_cn},CN=Users,{realm_dn}",);
                    ldap.add(
                        &user_dn,
                        vec![
                            ("cn".as_bytes(), [principal_cn.as_bytes()].into()),
                            ("objectClass".as_bytes(), ["user".as_bytes()].into()),
                            ("instanceType".as_bytes(), ["4".as_bytes()].into()),
                            (
                                "objectCategory".as_bytes(),
                                ["CN=Container,CN=Schema,CN=Configuration,DC=sble,DC=test"
                                    .as_bytes()]
                                .into(),
                            ),
                            ("unicodePwd".as_bytes(), [&*password_ad_encoded].into()),
                            ("userAccountControl".as_bytes(), ["66048".as_bytes()].into()),
                            (
                                "userPrincipalName".as_bytes(),
                                [
                                    format!("{principal}@{realm_name}", principal = princ_req.name)
                                        .as_bytes(),
                                ]
                                .into(),
                            ),
                        ],
                    )
                    .await
                    .unwrap()
                    .success()
                    .unwrap();
                    // CONCURRENCY: ldap.add() will only succeed once per principal, so
                    // we are by definition the unique writer of this key.
                    // FIXME: What about cases where ldap.add() succeeds but not the cache write?
                    kube.merge_patch(
                        &password_cache,
                        &Secret {
                            data: Some([(password_cache_key, ByteString(password.into()))].into()),
                            ..Secret::default()
                        },
                    )
                    .await
                    .unwrap();
                    Vec::<u8>::from(password)
                };
                kt.add(
                    &princ,
                    0,
                    &Keyblock::from_password(
                        &krb,
                        krb5::enctype::AES256_CTS_HMAC_SHA1_96,
                        &CString::new(password).unwrap(),
                        &princ.default_salt().unwrap(),
                    )
                    .unwrap()
                    .as_ref(),
                )
                .unwrap();
            }
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
