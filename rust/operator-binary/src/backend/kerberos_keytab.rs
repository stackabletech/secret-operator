use std::{convert::Infallible, ffi::CString};

use async_trait::async_trait;
use krb5_sys::kadm5_randkey_principal_3;
use snafu::{ResultExt, Snafu};

use super::{SecretBackend, SecretBackendError};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to initialize krb5"))]
    KrbInit { source: kadm5::KrbError },
    #[snafu(display("failed to initialize kadmin"))]
    KadminInit { source: kadm5::KadmError },
}
impl SecretBackendError for Error {
    fn grpc_code(&self) -> tonic::Code {
        match self {
            Self::KrbInit { .. } => tonic::Code::Unavailable,
            Self::KadminInit { .. } => tonic::Code::Unavailable,
        }
    }
}

pub struct KerberosKeytab {}

#[async_trait]
impl SecretBackend for KerberosKeytab {
    type Error = Error;

    async fn get_secret_data(
        &self,
        _selector: super::SecretVolumeSelector,
        _pod_info: super::pod_info::PodInfo,
    ) -> Result<super::SecretFiles, Self::Error> {
        // kadm5_randkey_principal_3(server_handle, principal, keepold, n_ks_tuple, ks_tuple, keyblocks, n_keys)
        let config_params = kadm5::ConfigParams {
            default_realm: Some(CString::new("ASDF").unwrap()),
        };
        let krb = kadm5::KrbContext::new().context(KrbInitSnafu)?;
        let kadmin = kadm5::ServerHandle::new(
            &krb,
            &CString::new("stackable-secret-operator@ASDF").unwrap(),
            &kadm5::Credential::ServiceKey {
                keytab: CString::new("").unwrap(),
                service_name: CString::new("").unwrap(),
            },
            &config_params,
        )
        .context(KadminInitSnafu)?;
        todo!()
    }
}

mod kadm5 {
    use std::{
        ffi::{CStr, CString},
        fmt::Display,
    };

    use krb5_sys::{kadm5_destroy, kadm5_init_with_skey};
    use snafu::Snafu;

    #[derive(Debug)]
    pub struct KadmError {
        code: krb5_sys::kadm5_ret_t,
    }
    impl KadmError {
        fn from_ret(code: krb5_sys::kadm5_ret_t) -> Result<(), Self> {
            if code.0 == krb5_sys::kadm5_ret_t(krb5_sys::KADM5_OK.into()).0 {
                Ok(())
            } else {
                Err(Self { code })
            }
        }
    }
    impl std::error::Error for KadmError {}
    impl Display for KadmError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let msg = unsafe { CStr::from_ptr(krb5_sys::error_message(self.code.0)) };
            f.write_str(&msg.to_string_lossy())
        }
    }

    #[derive(Debug, Snafu)]
    pub struct KrbError {
        code: krb5_sys::krb5_error_code,
    }
    impl KrbError {
        fn from_code(code: krb5_sys::krb5_error_code) -> Result<(), Self> {
            if code.0 == 0 {
                Ok(())
            } else {
                Err(Self { code })
            }
        }
    }

    pub struct KrbContext {
        raw: krb5_sys::krb5_context,
    }
    impl KrbContext {
        pub fn new() -> Result<Self, KrbError> {
            let mut ctx = std::ptr::null_mut();
            KrbError::from_code(unsafe { krb5_sys::kadm5_init_krb5_context(&mut ctx) })?;
            Ok(Self { raw: ctx })
        }

        pub fn parse_name(&self, princ_name: &CStr) -> Result<Principal, KrbError> {
            let mut principal = std::ptr::null_mut();
            KrbError::from_code(unsafe {
                krb5_sys::krb5_parse_name(self.raw, princ_name.as_ptr(), &mut principal)
            })?;
            Ok(Principal {
                ctx: self,
                raw: principal,
            })
        }
    }
    impl Drop for KrbContext {
        fn drop(&mut self) {
            unsafe {
                krb5_sys::krb5_free_context(self.raw);
            }
        }
    }

    pub struct Principal<'a> {
        ctx: &'a KrbContext,
        raw: krb5_sys::krb5_principal,
    }
    impl Drop for Principal<'_> {
        fn drop(&mut self) {
            unsafe {
                krb5_sys::krb5_free_principal(self.ctx.raw, self.raw);
            }
        }
    }

    pub enum Credential {
        ServiceKey {
            keytab: CString,
            service_name: CString,
        },
    }

    #[derive(Default)]
    pub struct ConfigParams {
        pub default_realm: Option<CString>,
    }
    impl ConfigParams {
        /// Return a [`krb5_sys::kadm5_config_params`] view of `self`
        ///
        /// The returned `kadm5_config_params` has the same lifetime as `&self`. It
        /// should be considered unusable as soon as `self` is moved, modified,
        /// or dropped.
        fn as_c(&self) -> krb5_sys::kadm5_config_params {
            let mut c = unsafe { std::mem::zeroed::<krb5_sys::kadm5_config_params>() };
            if let Some(default_realm) = &self.default_realm {
                c.realm = default_realm.as_ptr() as *mut i8;
                c.mask |= i64::from(krb5_sys::KADM5_CONFIG_REALM);
            }
            c
        }
    }

    pub struct ServerHandle<'a> {
        ctx: &'a KrbContext,
        raw: *mut std::ffi::c_void,
    }
    impl<'a> ServerHandle<'a> {
        pub fn new(
            ctx: &'a KrbContext,
            client_name: &CStr,
            credential: &Credential,
            params: &ConfigParams,
        ) -> Result<Self, KadmError> {
            let mut server_handle = std::ptr::null_mut();
            let mut params = params.as_c();

            match credential {
                Credential::ServiceKey {
                    keytab,
                    service_name,
                } => unsafe {
                    KadmError::from_ret(kadm5_init_with_skey(
                        ctx.raw,
                        client_name.as_ptr() as *mut i8,
                        keytab.as_ptr() as *mut i8,
                        service_name.as_ptr() as *mut i8,
                        &mut params,
                        krb5_sys::KADM5_STRUCT_VERSION_1,
                        krb5_sys::KADM5_API_VERSION_4,
                        std::ptr::null_mut(),
                        &mut server_handle,
                    ))?;
                },
            }
            Ok(Self {
                ctx,
                raw: server_handle,
            })
        }

        pub fn generate_principal_keys(
            &self,
            principal: &Principal,
            keep_old: bool,
            keyset_id: i32,
            key_salt_tuple: krb5_sys::krb5_key_salt_tuple,
        ) -> Result<(), KadmError> {
            let mut keys = std::ptr::null_mut();
            let mut key_count = 0;

            KadmError::from_ret(unsafe {
                krb5_sys::kadm5_randkey_principal_3(
                    self.raw,
                    principal.raw,
                    if keep_old { 1 } else { 0 },
                    keyset_id,
                    std::ptr::null_mut(),
                    &mut keys,
                    &mut key_count,
                )
            })?;
            dbg!(keys);
            let keyblock = Keyblock {
                ctx: self.ctx,
                raw: keys,
                key_count,
            };
            Ok(())
        }
    }
    impl<'a> Drop for ServerHandle<'a> {
        fn drop(&mut self) {
            unsafe {
                KadmError::from_ret(kadm5_destroy(self.raw))
                    .expect("failed to destroy kadmin5 server handle");
            }
        }
    }

    struct Keyblock<'a> {
        ctx: &'a KrbContext,
        raw: *mut krb5_sys::krb5_keyblock,
        key_count: i32,
    }
    impl Drop for Keyblock<'_> {
        fn drop(&mut self) {
            unsafe { krb5_sys::krb5_free_keyblock(self.ctx.raw, self.raw) }
        }
    }
}
