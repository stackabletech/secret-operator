use std::{
    ffi::{c_int, CStr, CString},
    fmt::Display,
    slice,
};

use crate::{KeyblockRef, KrbContext, Principal};

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

pub enum Credential {
    ServiceKey { keytab: CString },
}

#[derive(Default)]
pub struct ConfigParams {
    pub default_realm: Option<CString>,
    pub admin_server: Option<CString>,
    pub kadmind_port: Option<i32>,
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
        if let Some(admin_server) = &self.admin_server {
            c.admin_server = admin_server.as_ptr() as *mut i8;
            c.mask |= i64::from(krb5_sys::KADM5_CONFIG_ADMIN_SERVER);
        }
        if let Some(kadmind_port) = self.kadmind_port {
            c.kadmind_port = kadmind_port;
            c.mask |= i64::from(krb5_sys::KADM5_CONFIG_KADMIND_PORT);
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
        service_name: Option<&CStr>,
        credential: &Credential,
        params: &ConfigParams,
    ) -> Result<Self, KadmError> {
        let mut server_handle = std::ptr::null_mut();
        let mut params = params.as_c();

        match credential {
            Credential::ServiceKey { keytab } => unsafe {
                KadmError::from_ret(krb5_sys::kadm5_init_with_skey(
                    ctx.raw,
                    client_name.as_ptr().cast_mut(),
                    keytab.as_ptr().cast_mut(),
                    service_name
                        .as_ref()
                        .map_or(std::ptr::null_mut(), |sn| sn.as_ptr().cast_mut()),
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

    // pub fn generate_principal_keys(
    //     &self,
    //     principal: &Principal,
    //     keep_old: bool,
    //     keyset_id: i32,
    //     key_salt_tuple: krb5_sys::krb5_key_salt_tuple,
    // ) -> Result<(), KadmError> {
    //     let mut keys = std::ptr::null_mut();
    //     let mut key_count = 0;

    //     KadmError::from_ret(unsafe {
    //         krb5_sys::kadm5_randkey_principal_3(
    //             self.raw,
    //             principal.raw,
    //             keep_old.into(),
    //             keyset_id,
    //             std::ptr::null_mut(),
    //             &mut keys,
    //             &mut key_count,
    //         )
    //     })?;
    //     dbg!(keys);
    //     let keyblock = Keyblock {
    //         ctx: self.ctx,
    //         raw: keys,
    //         key_count,
    //     };
    //     Ok(())
    // }

    pub fn get_principal_keys(
        &self,
        principal: &Principal,
        kvno: krb5_sys::krb5_kvno,
    ) -> Result<KeyDataVec, KadmError> {
        let mut key_data = std::ptr::null_mut();
        let mut key_count = 0;
        unsafe {
            KadmError::from_ret(krb5_sys::kadm5_get_principal_keys(
                self.raw,
                principal.raw,
                kvno,
                &mut key_data,
                &mut key_count,
            ))?;
        }
        Ok(KeyDataVec {
            ctx: self.ctx,
            raw: key_data,
            key_count,
        })
    }
}
impl<'a> Drop for ServerHandle<'a> {
    fn drop(&mut self) {
        unsafe {
            KadmError::from_ret(krb5_sys::kadm5_destroy(self.raw))
                .expect("failed to destroy kadmin5 server handle");
        }
    }
}

pub struct KeyDataRef<'a> {
    pub kvno: krb5_sys::krb5_kvno,
    pub keyblock: KeyblockRef<'a>,
    salt: krb5_sys::krb5_keysalt,
}
pub struct KeyDataVec<'a> {
    ctx: &'a KrbContext,
    raw: *mut krb5_sys::kadm5_key_data,
    key_count: c_int,
}
impl KeyDataVec<'_> {
    fn as_slice(&self) -> &[krb5_sys::kadm5_key_data] {
        unsafe {
            slice::from_raw_parts(
                self.raw,
                self.key_count
                    .try_into()
                    .expect("keydata vec must have a non-negative number of keys"),
            )
        }
    }

    #[allow(clippy::needless_lifetimes)]
    pub fn keys<'a>(&'a self) -> impl Iterator<Item = KeyDataRef<'a>> {
        self.as_slice().iter().map(|raw| KeyDataRef {
            kvno: raw.kvno,
            keyblock: KeyblockRef {
                ctx: self.ctx,
                raw: &raw.key,
            },
            salt: raw.salt,
        })
    }
}
impl Drop for KeyDataVec<'_> {
    fn drop(&mut self) {
        KadmError::from_ret(unsafe {
            krb5_sys::kadm5_free_kadm5_key_data(self.ctx.raw, self.key_count, self.raw)
        })
        .unwrap()
    }
}
