use std::{
    collections::BTreeMap,
    ffi::{CString, NulError},
    fmt::Display,
};

use byteorder::{LittleEndian, WriteBytesExt};
use krb5::{Keyblock, Keytab, KrbContext, Principal, PrincipalUnparseOptions};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use rand::{seq::SliceRandom, thread_rng, CryptoRng};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_operator::{
    k8s_openapi::{
        api::core::v1::{Secret, SecretReference},
        ByteString,
    },
    kube::runtime::reflector::ObjectRef,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("LDAP TLS CA reference is invalid"))]
    LdapTlsCaReferenceInvalid { source: IncompleteSecretRef },
    #[snafu(display("failed to retrieve LDAP TLS CA {ca_ref}"))]
    GetLdapTlsCa {
        source: stackable_operator::error::Error,
        ca_ref: FullSecretRef,
    },
    #[snafu(display("LDAP TLS CA secret is missing required key {key}"))]
    LdapTlsCaKeyMissing { key: String },
    #[snafu(display("failed to parse LDAP TLS CA"))]
    ParseLdapTlsCa { source: native_tls::Error },
    #[snafu(display("password cache reference is invalid"))]
    PasswordCacheReferenceInvalid { source: IncompleteSecretRef },
    #[snafu(display("failed to configure LDAP TLS"))]
    ConfigureLdapTls { source: native_tls::Error },
    #[snafu(display("failed to connect to LDAP server"))]
    ConnectLdap { source: ldap3::LdapError },
    #[snafu(display("failed to authenticate to LDAP server"))]
    LdapAuthn { source: ldap3::LdapError },
    #[snafu(display("failed to init Kubernetes client"))]
    KubeInit {
        source: stackable_operator::error::Error,
    },

    #[snafu(display("failed to unparse Kerberos principal"))]
    UnparsePrincipal { source: krb5::Error },
    #[snafu(display("failed to get password cache {password_cache_ref}"))]
    GetPasswordCache {
        source: stackable_operator::error::Error,
        password_cache_ref: FullSecretRef,
    },
    #[snafu(display("failed to update password cache {password_cache_ref}"))]
    UpdatePasswordCache {
        source: stackable_operator::error::Error,
        password_cache_ref: FullSecretRef,
    },
    #[snafu(display("failed to create LDAP user"))]
    CreateLdapUser { source: ldap3::LdapError },
    #[snafu(display(
        "LDAP user already exists, either delete it manually or add it to the password cache ({password_cache_ref})"
    ))]
    CreateLdapUserConflict {
        source: ldap3::LdapError,
        password_cache_ref: FullSecretRef,
    },
    #[snafu(display("failed to decode generated password"))]
    DecodePassword { source: NulError },
    #[snafu(display("failed to add key to keytab"))]
    AddToKeytab { source: krb5::Error },
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

// Result codes are defined by https://www.rfc-editor.org/rfc/rfc4511#appendix-A.1
const LDAP_RESULT_CODE_ENTRY_ALREADY_EXISTS: u32 = 68;

pub struct AdAdmin<'a> {
    ldap: Ldap,
    krb: &'a KrbContext,
    kube: stackable_operator::client::Client,
    password_cache_ref: FullSecretRef,
    user_distinguished_name: String,
    schema_distinguished_name: String,
}

impl<'a> AdAdmin<'a> {
    pub async fn connect(
        ldap_server: &str,
        krb: &'a KrbContext,
        ldap_tls_ca_secret: SecretReference,
        password_cache_secret: SecretReference,
        user_distinguished_name: String,
        schema_distinguished_name: String,
    ) -> Result<AdAdmin<'a>> {
        let kube = stackable_operator::client::create_client(None)
            .await
            .context(KubeInitSnafu)?;
        let ldap_tls = native_tls::TlsConnector::builder()
            .disable_built_in_roots(true)
            .add_root_certificate(get_ldap_ca_certificate(&kube, ldap_tls_ca_secret).await?)
            .build()
            .context(ConfigureLdapTlsSnafu)?;
        let (ldap_conn, mut ldap) = LdapConnAsync::with_settings(
            LdapConnSettings::new().set_connector(ldap_tls),
            &format!("ldaps://{ldap_server}"),
        )
        .await
        .context(ConnectLdapSnafu)?;
        ldap3::drive!(ldap_conn);
        ldap.sasl_gssapi_bind(ldap_server)
            .await
            .context(LdapAuthnSnafu)?;
        Ok(Self {
            ldap,
            krb,
            kube,
            password_cache_ref: password_cache_secret
                .try_into()
                .context(PasswordCacheReferenceInvalidSnafu)?,
            user_distinguished_name,
            schema_distinguished_name,
        })
    }

    #[tracing::instrument(skip(self, principal, kt), fields(principal = %principal))]
    pub async fn create_and_add_principal_to_keytab(
        &mut self,
        principal: &Principal<'_>,
        kt: &mut Keytab<'_>,
    ) -> Result<()> {
        let princ_name = principal
            .unparse(PrincipalUnparseOptions::default())
            .context(UnparsePrincipalSnafu)?;
        let princ_name_realmless = principal
            .unparse(PrincipalUnparseOptions {
                realm: krb5::PrincipalRealmDisplayMode::Never,
                ..Default::default()
            })
            .context(UnparsePrincipalSnafu)?;
        let mut password_cache = self
            .kube
            .get::<Secret>(
                &self.password_cache_ref.name,
                &self.password_cache_ref.namespace,
            )
            .await
            .with_context(|_| GetPasswordCacheSnafu {
                password_cache_ref: &self.password_cache_ref,
            })?;
        let password_cache_key = princ_name.replace(['/', '@'], "--");
        let password = if let Some(pw) = password_cache
            .data
            .get_or_insert_with(BTreeMap::default)
            .get(&password_cache_key)
        {
            tracing::info!(
                cache = %self.password_cache_ref,
                cache_key = password_cache_key,
                "found principal in password cache, reusing"
            );
            pw.0.clone()
        } else {
            tracing::info!(
                cache = %self.password_cache_ref,
                cache_key = password_cache_key,
                "did not find principal in password cache, creating"
            );
            tracing::info!("creating principal");
            let principal_cn = ldap3::dn_escape(&princ_name);
            // FIXME: AD restricts RDNs to 64 characters
            let principal_cn = principal_cn.get(..64).unwrap_or(&*principal_cn);
            let password = generate_ad_password(40);
            let password_ad_encoded = {
                let mut pwd_utf16le = Vec::new();
                format!("\"{password}\"").encode_utf16().for_each(|word| {
                    WriteBytesExt::write_u16::<LittleEndian>(&mut pwd_utf16le, word)
                        .expect("writing into a string is infallible")
                });
                pwd_utf16le
            };
            let user_dn = format!("CN={principal_cn},{}", self.user_distinguished_name);
            let create_user_result =
                self.ldap
                    .add(
                        &user_dn,
                        vec![
                            ("cn".as_bytes(), [principal_cn.as_bytes()].into()),
                            ("objectClass".as_bytes(), ["user".as_bytes()].into()),
                            ("instanceType".as_bytes(), ["4".as_bytes()].into()),
                            (
                                "objectCategory".as_bytes(),
                                [format!("CN=Container,{}", self.schema_distinguished_name)
                                    .as_bytes()]
                                .into(),
                            ),
                            ("unicodePwd".as_bytes(), [&*password_ad_encoded].into()),
                            ("userAccountControl".as_bytes(), ["66048".as_bytes()].into()),
                            (
                                "userPrincipalName".as_bytes(),
                                [princ_name.as_bytes()].into(),
                            ),
                            (
                                "servicePrincipalName".as_bytes(),
                                [princ_name_realmless.as_bytes()].into(),
                            ),
                            (
                                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
                                "msDS-SupportedEncryptionTypes".as_bytes(),
                                ["24".as_bytes()].into(),
                            ),
                        ],
                    )
                    .await
                    .context(CreateLdapUserSnafu)?;
            match create_user_result.rc {
                LDAP_RESULT_CODE_ENTRY_ALREADY_EXISTS => {
                    create_user_result
                        .success()
                        .context(CreateLdapUserConflictSnafu {
                            password_cache_ref: &self.password_cache_ref,
                        })?
                }
                _ => create_user_result.success().context(CreateLdapUserSnafu)?,
            };
            // CONCURRENCY: ldap.add() will only succeed once per principal, so
            // we are by definition the unique writer of this key.
            // FIXME: What about cases where ldap.add() succeeds but not the cache write?
            self.kube
                .merge_patch(
                    &password_cache,
                    &Secret {
                        data: Some(
                            [(password_cache_key, ByteString(password.as_str().into()))].into(),
                        ),
                        ..Secret::default()
                    },
                )
                .await
                .context(UpdatePasswordCacheSnafu {
                    password_cache_ref: &self.password_cache_ref,
                })?;
            Vec::<u8>::from(password)
        };
        let password_c = CString::new(password).context(DecodePasswordSnafu)?;
        principal
            .default_salt()
            .and_then(|salt| {
                Keyblock::from_password(
                    self.krb,
                    krb5::enctype::AES256_CTS_HMAC_SHA1_96,
                    &password_c,
                    &salt,
                )
            })
            .and_then(|key| kt.add(principal, 0, &key.as_ref()))
            .context(AddToKeytabSnafu)?;
        Ok(())
    }
}

#[derive(Debug, Snafu)]
#[snafu(display("secret ref is missing {field}"))]
pub struct IncompleteSecretRef {
    field: String,
}
#[derive(Debug, Clone)]
pub struct FullSecretRef {
    name: String,
    namespace: String,
}
impl TryFrom<SecretReference> for FullSecretRef {
    type Error = IncompleteSecretRef;

    fn try_from(secret_ref: SecretReference) -> Result<Self, IncompleteSecretRef> {
        Ok(Self {
            name: secret_ref
                .name
                .context(IncompleteSecretRefSnafu { field: "name" })?,
            namespace: secret_ref
                .namespace
                .context(IncompleteSecretRefSnafu { field: "namespace" })?,
        })
    }
}
impl From<&FullSecretRef> for FullSecretRef {
    fn from(pcr: &FullSecretRef) -> Self {
        pcr.clone()
    }
}
impl Display for FullSecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ObjectRef::<Secret>::new(&self.name)
            .within(&self.namespace)
            .fmt(f)
    }
}

async fn get_ldap_ca_certificate(
    kube: &stackable_operator::client::Client,
    ca_secret_ref: SecretReference,
) -> Result<native_tls::Certificate> {
    let ca_secret_ref: FullSecretRef = ca_secret_ref
        .try_into()
        .context(LdapTlsCaReferenceInvalidSnafu)?;
    let ca_secret = kube
        .get::<Secret>(&ca_secret_ref.name, &ca_secret_ref.namespace)
        .await
        .context(GetLdapTlsCaSnafu {
            ca_ref: ca_secret_ref,
        })?;
    let ca_key = "ca.crt";
    let ca_cert_pem = ca_secret
        .data
        .and_then(|mut d| d.remove(ca_key))
        .map(|ca| ca.0)
        .context(LdapTlsCaKeyMissingSnafu { key: ca_key })?;
    native_tls::Certificate::from_pem(&ca_cert_pem).context(ParseLdapTlsCaSnafu)
}

fn generate_ad_password(len: usize) -> String {
    let mut rng = thread_rng();
    // Assert that `rng` is crypto-safe
    let _: &dyn CryptoRng = &rng;
    // Allow all ASCII alphanumeric characters as well as punctuation
    // Exclude double quotes (") since they are used by the AD password update protocol...
    let dict: Vec<char> = (1..=127)
        .filter_map(char::from_u32)
        .filter(|c| *c != '"' && (c.is_ascii_alphanumeric() || c.is_ascii_punctuation()))
        .collect();
    let pw = (0..len)
        .map(|_| *dict.choose(&mut rng).expect("dictionary must be non-empty"))
        .collect::<String>();
    assert_eq!(pw.len(), len);
    pw
}