use std::{
    ffi::{CStr, CString, c_char},
    fmt::Display,
};

#[derive(Debug)]
pub struct ProfileError {
    code: i64,
}
impl ProfileError {
    fn from_code(code: i64) -> Result<(), Self> {
        if code == 0 {
            Ok(())
        } else {
            Err(Self { code })
        }
    }
}
impl std::error::Error for ProfileError {}
impl Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = unsafe { CStr::from_ptr(krb5_sys::error_message(self.code)) };
        f.write_str(&msg.to_string_lossy())
    }
}

/// A Kerberos configuration profile. This is equivalent to a krb5.conf file.
///
/// Any modifications made are lost when dropped. In other words, [`Drop::drop`] is equivalent to
/// [`krb5_sys::profile_abandon`], _not_ [`krb5_sys::profile_release`]. To save any changes, use
/// [`Self::flush`].
pub struct Profile {
    pub(super) raw: *mut krb5_sys::_profile_t,
}
impl Profile {
    /// Create a new empty profile.
    pub fn new() -> Result<Self, ProfileError> {
        // profile segfaults on writes if there isn't at least one file specified
        Self::from_path(&CString::new("/dev/null").unwrap())
    }

    /// Load a profile from a file.
    pub fn from_path(path: &CStr) -> Result<Self, ProfileError> {
        let mut files = [
            path.as_ptr(),
            // list of strings is null-terminated
            std::ptr::null(),
        ];
        let mut profile = std::ptr::null_mut::<krb5_sys::_profile_t>();
        ProfileError::from_code(unsafe {
            krb5_sys::profile_init(files.as_mut_ptr(), &mut profile)
        })?;
        Ok(Self { raw: profile })
    }

    /// Set a configuration value.
    pub fn set(&mut self, key_path: &[&CStr], value: &CStr) -> Result<(), ProfileError> {
        let mut key_path = key_path
            .iter()
            .map(|s| s.as_ptr())
            // Path is terminated by null pointer
            .chain([std::ptr::null()])
            .collect::<Vec<*const c_char>>();
        ProfileError::from_code(unsafe {
            krb5_sys::profile_add_relation(self.raw, key_path.as_mut_ptr(), value.as_ptr())
        })
    }

    /// Save any modifications made to the file, if it was created using [`Self::from_path`].
    pub fn flush(&mut self) -> Result<(), ProfileError> {
        ProfileError::from_code(unsafe { krb5_sys::profile_flush(self.raw) })
    }
}
impl Drop for Profile {
    fn drop(&mut self) {
        unsafe { krb5_sys::profile_abandon(self.raw) }
    }
}
