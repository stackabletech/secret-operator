use std::collections::HashMap;

pub use self::{
    convert::ConvertError,
    well_known::{FromFilesError as ParseError, SecretFormat, WellKnownSecretData},
};

mod convert;
mod utils;
pub mod well_known;

pub type SecretFiles = HashMap<String, Vec<u8>>;

#[derive(Debug)]
pub enum SecretData {
    WellKnown(well_known::WellKnownSecretData),
    Unknown(SecretFiles),
}
impl SecretData {
    pub fn into_files(self) -> SecretFiles {
        match self {
            SecretData::WellKnown(data) => data.into_files(),
            SecretData::Unknown(files) => files,
        }
    }

    pub fn parse(self) -> Result<WellKnownSecretData, ParseError> {
        match self {
            Self::WellKnown(x) => Ok(x),
            Self::Unknown(files) => WellKnownSecretData::from_files(files),
        }
    }
}
