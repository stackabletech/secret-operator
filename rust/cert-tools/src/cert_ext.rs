use anyhow::Context;
use openssl::{
    hash::{DigestBytes, MessageDigest},
    string::OpensslString,
    x509::X509,
};

pub trait CertExt {
    fn serial_as_hex(&self) -> anyhow::Result<OpensslString>;
    fn sha256_digest(&self) -> anyhow::Result<DigestBytes>;
}

impl CertExt for X509 {
    fn serial_as_hex(&self) -> anyhow::Result<OpensslString> {
        self.serial_number()
            .to_bn()
            .context("failed to get certificate serial number as BigNumber")?
            .to_hex_str()
            .context("failed to convert certificate serial number to hex string")
    }

    fn sha256_digest(&self) -> anyhow::Result<DigestBytes> {
        self.digest(MessageDigest::sha256())
            .context("failed to get certificate digest")
    }
}
