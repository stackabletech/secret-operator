use std::{ffi::CStr, fmt::Display};

use krb5_sys::krb5_kt_resolve;
use profile::Profile;

pub mod kadm5;
pub mod profile;

#[derive(Debug)]
pub struct KrbError {
    message: String,
    code: krb5_sys::krb5_error_code,
}
impl KrbError {
    // safety: must be called exactly once, immediately after each potentially
    // error-generating call that interacts with ctx
    // ctx should be None iff the error happened during ctx init
    unsafe fn from_call_result(
        ctx: Option<&KrbContext>,
        code: krb5_sys::krb5_error_code,
    ) -> Result<(), Self> {
        if code.0 == 0 {
            Ok(())
        } else {
            let message = {
                // copy message into rust str, to avoid keeping a dependency on ctx
                // also, krb5_get_error_message may only be called once per error
                let raw_ctx = ctx.map_or(std::ptr::null_mut(), |c| c.raw);
                let c_msg = unsafe { krb5_sys::krb5_get_error_message(raw_ctx, code) };
                let rust_msg = CStr::from_ptr(c_msg).to_string_lossy().into_owned();
                unsafe { krb5_sys::krb5_free_error_message(raw_ctx, c_msg) }
                rust_msg
            };
            Err(Self { message, code })
        }
    }
}
impl std::error::Error for KrbError {}
impl Display for KrbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result where {
        // let msg = unsafe { CStr::from_ptr(krb5_sys::krb5_get_error_message(self.code.0)) };
        // f.write_str(&msg.to_string_lossy())
        f.write_str(&self.message)
    }
}

pub struct KrbContext {
    raw: krb5_sys::krb5_context,
}
impl KrbContext {
    pub fn new_kadm5() -> Result<Self, KrbError> {
        let mut ctx = std::ptr::null_mut();
        unsafe { KrbError::from_call_result(None, krb5_sys::kadm5_init_krb5_context(&mut ctx)) }?;
        Ok(Self { raw: ctx })
    }

    pub fn from_profile(profile: &Profile) -> Result<Self, KrbError> {
        let mut ctx = std::ptr::null_mut();
        unsafe {
            KrbError::from_call_result(
                None,
                krb5_sys::krb5_init_context_profile(profile.raw, 0, &mut ctx),
            )
        }?;
        Ok(Self { raw: ctx })
    }

    pub fn parse_name(&self, princ_name: &CStr) -> Result<Principal, KrbError> {
        let mut principal = std::ptr::null_mut();
        unsafe {
            KrbError::from_call_result(
                None,
                krb5_sys::krb5_parse_name(self.raw, princ_name.as_ptr(), &mut principal),
            )
        }?;
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

pub struct KeyblockRef<'a> {
    ctx: &'a KrbContext,
    raw: *const krb5_sys::krb5_keyblock,
    // key_count: i32,
}
struct Keyblock<'a>(KeyblockRef<'a>);
impl Drop for Keyblock<'_> {
    fn drop(&mut self) {
        unsafe { krb5_sys::krb5_free_keyblock(self.0.ctx.raw, self.0.raw.cast_mut()) }
    }
}

pub struct Keytab<'a> {
    ctx: &'a KrbContext,
    raw: krb5_sys::krb5_keytab,
}
impl<'a> Keytab<'a> {
    pub fn resolve(ctx: &'a KrbContext, name: &CStr) -> Result<Self, KrbError> {
        let mut raw = std::ptr::null_mut();
        unsafe {
            KrbError::from_call_result(
                Some(ctx),
                krb5_kt_resolve(ctx.raw, name.as_ptr(), &mut raw),
            )?
        }
        Ok(Self { ctx, raw })
    }

    pub fn add(
        &mut self,
        principal: &Principal,
        kvno: krb5_sys::krb5_kvno,
        keyblock: &KeyblockRef,
    ) -> Result<(), KrbError> {
        unsafe {
            let mut entry: krb5_sys::krb5_keytab_entry = std::mem::zeroed();
            entry.principal = principal.raw;
            entry.vno = kvno;
            entry.key = keyblock.raw.read();
            // safety: krb5_kt_add_entry is responsible for copying entry as needed
            KrbError::from_call_result(
                Some(self.ctx),
                krb5_sys::krb5_kt_add_entry(self.ctx.raw, self.raw, &mut entry),
            )
        }
    }
}
impl Drop for Keytab<'_> {
    fn drop(&mut self) {
        unsafe {
            KrbError::from_call_result(
                Some(self.ctx),
                krb5_sys::krb5_kt_close(self.ctx.raw, self.raw),
            )
            .unwrap()
        }
    }
}
