use std::collections::HashMap;

use snafu::Snafu;

use self::well_known::CompatibilityOptions;
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
    pub fn parse(self) -> Result<WellKnownSecretData, ParseError> {
        match self {
            Self::WellKnown(x) => Ok(x),
            Self::Unknown(files) => WellKnownSecretData::from_files(files),
        }
    }

    pub fn into_files(
        self,
        format: Option<SecretFormat>,
        compat: &CompatibilityOptions,
    ) -> Result<SecretFiles, IntoFilesError> {
        if let Some(format) = format {
            Ok(self.parse()?.convert_to(format, compat)?.into_files())
        } else {
            Ok(match self {
                SecretData::WellKnown(data) => data.into_files(),
                SecretData::Unknown(files) => files,
            })
        }
    }
}

#[derive(Snafu, Debug)]
pub enum IntoFilesError {
    #[snafu(display("failed to parse secret data"), context(false))]
    Parse { source: ParseError },

    #[snafu(
        display("failed to convert secret data into desired format"),
        context(false)
    )]
    Convert { source: ConvertError },
}
