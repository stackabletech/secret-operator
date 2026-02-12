use std::collections::HashMap;

use snafu::Snafu;

use self::well_known::CompatibilityOptions;
pub use self::{
    convert::ConvertError,
    well_known::{FromFilesError as ParseError, SecretFormat, WellKnownSecretData},
};
use crate::format::well_known::NamingOptions;

mod convert;
pub mod well_known;

pub type SecretFiles = HashMap<String, Vec<u8>>;

#[derive(Debug)]
pub enum SecretData {
    WellKnown(well_known::WellKnownSecretData),
    Unknown(SecretFiles),
}
impl SecretData {
    pub fn parse(self, relaxed: bool) -> Result<WellKnownSecretData, ParseError> {
        match self {
            Self::WellKnown(data) => Ok(data),
            Self::Unknown(files) => WellKnownSecretData::from_files(files, relaxed),
        }
    }

    pub fn into_files(
        self,
        format: Option<SecretFormat>,
        names: NamingOptions,
        compat: CompatibilityOptions,
        relaxed: bool,
    ) -> Result<SecretFiles, IntoFilesError> {
        let files = if let Some(format) = format {
            tracing::debug!(
                ?format,
                ?names,
                relaxed,
                "Explicit format requested: parsing and converting to transform into files"
            );

            self.parse(relaxed)?
                .convert_to(format, compat)?
                .into_files(names)
        } else {
            match self {
                SecretData::WellKnown(data) => data.into_files(names),
                SecretData::Unknown(files) => files,
            }
        };

        Ok(files)
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
