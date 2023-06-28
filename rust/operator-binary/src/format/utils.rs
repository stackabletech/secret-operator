/// Splits a byte sequence of PEM-encoded certificates.
pub fn split_pem_certificates(pem: &[u8]) -> impl Iterator<Item = &[u8]> {
    SplitPemCertificates {
        pem_iter: pem.iter(),
    }
}
struct SplitPemCertificates<'a> {
    pem_iter: std::slice::Iter<'a, u8>,
}
impl<'a> Iterator for SplitPemCertificates<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        const HEADER: &[u8] = b"-----BEGIN CERTIFICATE-----";
        let slice = self.pem_iter.as_slice();
        if slice.is_empty() {
            return None;
        }
        let mut len = 0;
        while let Some(chr) = self.pem_iter.next() {
            len += 1;
            if *chr == b'\n' && self.pem_iter.as_slice().starts_with(HEADER) {
                break;
            }
        }
        Some(&slice[..len])
    }
}

#[cfg(test)]
mod tests {
    use crate::format::utils::split_pem_certificates;

    #[test]
    fn test_split_pem_certificates() {
        assert_eq!(
            split_pem_certificates(
                b"-----BEGIN CERTIFICATE-----
foo
-----BEGIN CERTIFICATE-----
bar
-----BEGIN CERTIFICATE-----
baz
"
            )
            .collect::<Vec<_>>(),
            vec![
                b"-----BEGIN CERTIFICATE-----
foo
",
                b"-----BEGIN CERTIFICATE-----
bar
",
                b"-----BEGIN CERTIFICATE-----
baz
",
            ]
        )
    }
}
