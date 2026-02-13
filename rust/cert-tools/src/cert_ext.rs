use openssl::{
    hash::{DigestBytes, MessageDigest},
    string::OpensslString,
    x509::X509,
};
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to convert certificate serial number to BigNum"))]
    ConvertSerialToBigNum { source: openssl::error::ErrorStack },

    #[snafu(display("failed to convert certificate serial number to a hexadecimal string"))]
    ConvertSerialToHexString { source: openssl::error::ErrorStack },

    #[snafu(display("failed to retireve certificate digest as SHA256"))]
    RetrieveDigest { source: openssl::error::ErrorStack },
}

pub trait CertExt {
    fn serial_as_hex(&self) -> Result<OpensslString, Error>;
    fn sha256_digest(&self) -> Result<DigestBytes, Error>;
}

impl CertExt for X509 {
    fn serial_as_hex(&self) -> Result<OpensslString, Error> {
        self.serial_number()
            .to_bn()
            .context(ConvertSerialToBigNumSnafu)?
            .to_hex_str()
            .context(ConvertSerialToHexStringSnafu)
    }

    fn sha256_digest(&self) -> Result<DigestBytes, Error> {
        self.digest(MessageDigest::sha256())
            .context(RetrieveDigestSnafu)
    }
}
