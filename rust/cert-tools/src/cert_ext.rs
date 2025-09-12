use openssl::{
    hash::{DigestBytes, MessageDigest},
    string::OpensslString,
    x509::X509,
};
use snafu::ResultExt;

pub trait CertExt {
    fn serial_as_hex(&self) -> Result<OpensslString, snafu::Whatever>;
    fn sha256_digest(&self) -> Result<DigestBytes, snafu::Whatever>;
}

impl CertExt for X509 {
    fn serial_as_hex(&self) -> Result<OpensslString, snafu::Whatever> {
        self.serial_number()
            .to_bn()
            .whatever_context("failed to get certificate serial number as BigNumber")?
            .to_hex_str()
            .whatever_context("failed to convert certificate serial number to hex string")
    }

    fn sha256_digest(&self) -> Result<DigestBytes, snafu::Whatever> {
        self.digest(MessageDigest::sha256())
            .whatever_context("failed to get certificate digest")
    }
}
