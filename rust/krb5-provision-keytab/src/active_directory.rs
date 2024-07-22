use std::{
    collections::HashSet,
    ffi::{CString, NulError},
};

use byteorder::{LittleEndian, WriteBytesExt};
use krb5::{Keyblock, Keytab, KrbContext, Principal, PrincipalUnparseOptions};
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings};
use rand::{seq::SliceRandom, thread_rng, CryptoRng};
use snafu::{OptionExt, ResultExt, Snafu};
use stackable_krb5_provision_keytab::ActiveDirectorySamAccountNameRules;
use stackable_operator::{k8s_openapi::api::core::v1::Secret, kube::runtime::reflector::ObjectRef};
use stackable_secret_operator_crd_utils::SecretReference;

use crate::credential_cache::{self, CredentialCache};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to retrieve LDAP TLS CA {ca_ref}"))]
    GetLdapTlsCa {
        source: stackable_operator::client::Error,
        ca_ref: ObjectRef<Secret>,
    },

    #[snafu(display("LDAP TLS CA secret is missing required key {key}"))]
    LdapTlsCaKeyMissing { key: String },

    #[snafu(display("failed to parse LDAP TLS CA"))]
    ParseLdapTlsCa { source: native_tls::Error },

    #[snafu(display("password cache error"))]
    PasswordCache { source: credential_cache::Error },

    #[snafu(display("failed to configure LDAP TLS"))]
    ConfigureLdapTls { source: native_tls::Error },

    #[snafu(display("failed to connect to LDAP server"))]
    ConnectLdap { source: ldap3::LdapError },

    #[snafu(display("failed to authenticate to LDAP server"))]
    LdapAuthn { source: ldap3::LdapError },

    #[snafu(display("failed to init Kubernetes client"))]
    KubeInit {
        source: stackable_operator::client::Error,
    },

    #[snafu(display("failed to unparse Kerberos principal"))]
    UnparsePrincipal { source: krb5::Error },

    #[snafu(display("failed to create LDAP user"))]
    CreateLdapUser { source: ldap3::LdapError },

    #[snafu(display(
        "LDAP user already exists but is missing from the password cache ({password_cache_ref}) (hint: see {link})",
        link = "https://docs.stackable.tech/home/nightly/secret-operator/troubleshooting.html#active-directory-ldap-user-conflict"
    ))]
    CreateLdapUserConflict {
        source: ldap3::LdapError,
        password_cache_ref: ObjectRef<Secret>,
    },

    #[snafu(display("failed to decode generated password"))]
    DecodePassword { source: NulError },

    #[snafu(display("failed to add key to keytab"))]
    AddToKeytab { source: krb5::Error },

    #[snafu(display("configured samAccountName prefix is longer than the requested length"))]
    SamAccountNamePrefixLongerThanRequestedLength,
}
pub type Result<T, E = Error> = std::result::Result<T, E>;

// Result codes are defined by https://www.rfc-editor.org/rfc/rfc4511#appendix-A.1
const LDAP_RESULT_CODE_CONSTRAINT_VIOLATION: u32 = 19;
const LDAP_RESULT_CODE_ENTRY_ALREADY_EXISTS: u32 = 68;

// Error codes from https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/spn-and-upn-uniqueness#symptoms.
// Rendered in LDAP error messages as 8 zero-padded hex digits.
// BEST-EFFORT ONLY. THE SPECIFIC FORMAT IS NOT DOCUMENTED.
const AD_CONSTRAINT_PREFIX_UPN_VALUE_NOT_UNIQUE: &str = "000021C8:";

pub struct AdAdmin<'a> {
    ldap: Ldap,
    krb: &'a KrbContext,
    password_cache: CredentialCache,
    user_distinguished_name: String,
    schema_distinguished_name: String,
    generate_sam_account_name: Option<ActiveDirectorySamAccountNameRules>,
}

impl<'a> AdAdmin<'a> {
    pub async fn connect(
        ldap_server: &str,
        krb: &'a KrbContext,
        ldap_tls_ca_secret: SecretReference,
        password_cache_secret: SecretReference,
        user_distinguished_name: String,
        schema_distinguished_name: String,
        generate_sam_account_name: Option<ActiveDirectorySamAccountNameRules>,
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
        let password_cache = CredentialCache::new("AD passwords", kube, password_cache_secret)
            .await
            .context(PasswordCacheSnafu)?;
        Ok(Self {
            ldap,
            krb,
            password_cache,
            user_distinguished_name,
            schema_distinguished_name,
            generate_sam_account_name,
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
        let password_cache_key = princ_name.replace(['/', '@'], "__");
        let password = self
            .password_cache
            // CONCURRENCY: ldap.add() will only succeed once per principal, so
            // we are by definition the unique writer of this key.
            .get_or_insert(&password_cache_key, |ctx| async {
                let password = generate_ad_password(40);
                create_ad_user(
                    &mut self.ldap,
                    principal,
                    &password,
                    &self.user_distinguished_name,
                    &self.schema_distinguished_name,
                    ctx.cache_ref,
                    self.generate_sam_account_name.as_ref(),
                )
                .await?;
                Ok(password.into_bytes())
            })
            .await
            // FIXME: What about cases where ldap.add() succeeds but not the cache write?
            .context(PasswordCacheSnafu)??;
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

async fn get_ldap_ca_certificate(
    kube: &stackable_operator::client::Client,
    ca_secret_ref: SecretReference,
) -> Result<native_tls::Certificate> {
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

fn generate_random_string(len: usize, dict: &[char]) -> String {
    let mut rng = thread_rng();
    // Assert that `rng` is crypto-safe
    let _: &dyn CryptoRng = &rng;
    let str = (0..len)
        .map(|_| *dict.choose(&mut rng).expect("dictionary must be non-empty"))
        .collect::<String>();
    assert_eq!(str.len(), len);
    str
}

fn generate_ad_password(len: usize) -> String {
    // Allow all ASCII alphanumeric characters as well as punctuation
    // Exclude double quotes (") since they are used by the AD password update protocol...
    let dict: Vec<char> = (1..=127)
        .filter_map(char::from_u32)
        .filter(|c| *c != '"' && (c.is_ascii_alphanumeric() || c.is_ascii_punctuation()))
        .collect();
    generate_random_string(len, &dict)
}

fn generate_username(len: usize) -> String {
    // Allow ASCII alphanumerics
    let dict: Vec<char> = (1..=127)
        .filter_map(char::from_u32)
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    generate_random_string(len, &dict)
}

fn encode_password_for_ad_update(password: &str) -> Vec<u8> {
    let mut pwd_utf16le = Vec::new();
    format!("\"{password}\"").encode_utf16().for_each(|word| {
        WriteBytesExt::write_u16::<LittleEndian>(&mut pwd_utf16le, word)
            .expect("writing into a string is infallible")
    });
    pwd_utf16le
}

#[tracing::instrument(skip(ldap, principal, password), fields(%principal))]
async fn create_ad_user(
    ldap: &mut Ldap,
    principal: &Principal<'_>,
    password: &str,
    user_dn_base: &str,
    schema_dn_base: &str,
    password_cache_ref: SecretReference,
    generate_sam_account_name: Option<&ActiveDirectorySamAccountNameRules>,
) -> Result<()> {
    // Flags are a subset of https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    const AD_UAC_NORMAL_ACCOUNT: u32 = 0x0200;
    const AD_UAC_DONT_EXPIRE_PASSWORD: u32 = 0x1_0000;

    // Flags are a subset of https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
    const AD_ENCTYPE_AES128_HMAC_SHA1: u32 = 0x08;
    const AD_ENCTYPE_AES256_HMAC_SHA1: u32 = 0x10;

    tracing::info!("creating principal");
    let princ_name = principal
        .unparse(PrincipalUnparseOptions::default())
        .context(UnparsePrincipalSnafu)?;
    let princ_name_realmless = principal
        .unparse(PrincipalUnparseOptions {
            realm: krb5::PrincipalRealmDisplayMode::Never,
            ..Default::default()
        })
        .context(UnparsePrincipalSnafu)?;
    let principal_cn = ldap3::dn_escape(&princ_name);
    // FIXME: AD restricts RDNs to 64 characters
    let principal_cn = principal_cn.get(..64).unwrap_or(&*principal_cn);
    let sam_account_name = generate_sam_account_name
        .map(|sam_rules| {
            let mut name = sam_rules.prefix.clone();
            let random_part_len = usize::from(sam_rules.total_length)
                .checked_sub(name.len())
                .context(SamAccountNamePrefixLongerThanRequestedLengthSnafu)?;
            name += &generate_username(random_part_len);
            Ok(name)
        })
        .transpose()?;
    let create_user_result = ldap
        .add(
            &format!("CN={principal_cn},{user_dn_base}"),
            [
                ("cn".as_bytes(), [principal_cn.as_bytes()].into()),
                ("objectClass".as_bytes(), ["user".as_bytes()].into()),
                ("instanceType".as_bytes(), ["4".as_bytes()].into()),
                (
                    "objectCategory".as_bytes(),
                    [format!("CN=Container,{schema_dn_base}").as_bytes()].into(),
                ),
                (
                    "unicodePwd".as_bytes(),
                    [&*encode_password_for_ad_update(password)].into(),
                ),
                (
                    "userAccountControl".as_bytes(),
                    [(AD_UAC_NORMAL_ACCOUNT | AD_UAC_DONT_EXPIRE_PASSWORD)
                        .to_string()
                        .as_bytes()]
                    .into(),
                ),
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
                    [(AD_ENCTYPE_AES128_HMAC_SHA1 | AD_ENCTYPE_AES256_HMAC_SHA1)
                        .to_string()
                        .as_bytes()]
                    .into(),
                ),
            ]
            .into_iter()
            .chain(
                sam_account_name
                    .as_ref()
                    .map(|san| ("samAccountName".as_bytes(), HashSet::from([san.as_bytes()]))),
            )
            .collect(),
        )
        .await
        .context(CreateLdapUserSnafu)?;
    match create_user_result.rc {
        LDAP_RESULT_CODE_ENTRY_ALREADY_EXISTS => create_user_result
            .success()
            .context(CreateLdapUserConflictSnafu { password_cache_ref })?,
        LDAP_RESULT_CODE_CONSTRAINT_VIOLATION
            if create_user_result
                .text
                .starts_with(AD_CONSTRAINT_PREFIX_UPN_VALUE_NOT_UNIQUE) =>
        {
            create_user_result
                .success()
                .context(CreateLdapUserConflictSnafu { password_cache_ref })?
        }
        _ => create_user_result.success().context(CreateLdapUserSnafu)?,
    };
    Ok(())
}
