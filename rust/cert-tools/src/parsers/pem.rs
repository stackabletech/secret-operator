use openssl::x509::X509;
use snafu::{ResultExt, Snafu};
use stackable_secret_operator_utils::pem::split_pem_certificates;

#[derive(Debug, Snafu)]
#[snafu(display("failed to parse bytes as PEM"))]
pub struct ParseError {
    source: openssl::error::ErrorStack,
}

pub fn parse_contents(pem_bytes: &[u8]) -> Result<Vec<X509>, ParseError> {
    let pems = split_pem_certificates(pem_bytes);
    pems.into_iter()
        .map(|pem| X509::from_pem(pem).context(ParseSnafu))
        .collect()
}
