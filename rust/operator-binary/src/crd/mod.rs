use std::{fmt::Display, ops::Deref};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use stackable_operator::schemars::{self, JsonSchema};

mod secret_class;
mod trust_store;

pub mod v1alpha1 {
    // NOTE (@Techassi): SecretClass v1alpha1 is unused and as such not exported.
    pub use crate::crd::trust_store::v1alpha1::*;
}

pub use secret_class::{SecretClass, SecretClassVersion};

pub mod v1alpha2 {
    pub use crate::crd::secret_class::v1alpha2::*;
}

pub use trust_store::{TrustStore, TrustStoreVersion};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InvalidKerberosPrincipal {
    #[snafu(display(
        "principal contains illegal characters (allowed: alphanumeric, /, @, -, _, and .)"
    ))]
    IllegalCharacter,

    #[snafu(display("principal may not start with a dash"))]
    StartWithDash,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(try_from = "String", into = "String")]
pub struct KerberosPrincipal(String);

impl TryFrom<String> for KerberosPrincipal {
    type Error = InvalidKerberosPrincipal;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with('-') {
            invalid_kerberos_principal::StartWithDashSnafu.fail()
        } else if value.contains(|chr: char| {
            !chr.is_alphanumeric()
                && chr != '/'
                && chr != '@'
                && chr != '.'
                && chr != '-'
                && chr != '_'
        }) {
            invalid_kerberos_principal::IllegalCharacterSnafu.fail()
        } else {
            Ok(KerberosPrincipal(value))
        }
    }
}

impl From<KerberosPrincipal> for String {
    fn from(value: KerberosPrincipal) -> Self {
        value.0
    }
}

impl Display for KerberosPrincipal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for KerberosPrincipal {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
