/// Splits a byte sequence of PEM-encoded certificates.
///
/// It can tolerate additional contents between the actual PEM certificates, as e.g. the
/// `openssl pkcs12` command produces.
pub fn split_pem_certificates(pem: &[u8]) -> Vec<&[u8]> {
    const HEADER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const FOOTER: &[u8] = b"-----END CERTIFICATE-----";

    let mut certs = Vec::new();
    let mut pos = 0;

    while pos + HEADER.len() <= pem.len() {
        // Find the next header
        if &pem[pos..pos + HEADER.len()] != HEADER {
            pos += 1;
            continue;
        }

        let start = pos;
        pos += HEADER.len();

        // Find the matching footer
        while pos + FOOTER.len() <= pem.len() {
            if &pem[pos..pos + FOOTER.len()] == FOOTER {
                pos += FOOTER.len(); // include footer
                certs.push(&pem[start..pos]);
                break;
            }
            pos += 1;
        }
    }

    certs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_pem_certificates() {
        assert_eq!(
            split_pem_certificates(
                b"-----BEGIN CERTIFICATE-----
foo
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
bar
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
baz
-----END CERTIFICATE-----
"
            ),
            vec![
                b"-----BEGIN CERTIFICATE-----
foo
-----END CERTIFICATE-----",
                b"-----BEGIN CERTIFICATE-----
bar
-----END CERTIFICATE-----",
                b"-----BEGIN CERTIFICATE-----
baz
-----END CERTIFICATE-----",
            ]
        )
    }

    #[test]
    fn test_split_openssl_cli_pkcs12_output() {
        // openssl pkcs12 -in truststore.p12 -password pass: -nokeys -legacy
        let cli_output = b"
Bag Attributes
    Trusted key usage (Oracle): <No Values>
subject=CN=secret-operator self-signed
issuer=CN=secret-operator self-signed
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIKt7H+4AWKFYwDQYJKoZIhvcNAQELBQAwJjEkMCIGA1UE
Awwbc2VjcmV0LW9wZXJhdG9yIHNlbGYtc2lnbmVkMB4XDTI1MDkwMzExMDIwMVoX
DTI1MDkwMzExMDgwMVowJjEkMCIGA1UEAwwbc2VjcmV0LW9wZXJhdG9yIHNlbGYt
c2lnbmVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviEC2WtidVLN
qU6BO8qQ3PPThYBfia6UbfU8y5k8qPKHOJhYjtCKPTqCD82ht/UgzoXJ4zzqKL9B
2cBid+zj3/fxSRDKaPBMQvthC13M6zOz5ig/Ry24iaIaiz5ASDuqaQ9Hw/Y7viPB
pxkypTR59tYHa4+1D8xPtQCUixpxgxfRPAehZibrlP8TZrb6wSEjuicXljh9pevn
jw/TxFcNZVHgDw2N6RqhgaurcS/i4ScWxELXrdqi1K6G2twcWw2SPiU3xujXAMG7
lGISeJJnecD/rHzMT13TYqmbu65tSrVfG9YRqbGqgMfk5faFzCoIZZ447OA2coE7
JA/CJ3djVQIDAQABo00wSzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ1LwpK
L93s9BJgZpJ6vRnX2SzzMzAJBgNVHSMEAjAAMA4GA1UdDwEB/wQEAwIBhjANBgkq
hkiG9w0BAQsFAAOCAQEADOrNsdHBc4qf8wJNmm2RIRaepJDxsMiCmEh9A7JLFZEb
IsOIbynhAvfHCCZqSDeRNaMdxjKax6STy6QDy/U5jrwAFS1/1yFR7zqGE9IDOmrs
5uxDCYU23p1fIjvr+Uz7lk/EwXVTtqjzLAp+NP4YIQNFWfdKv6me3F2Czz4yfTRj
sZ5ggeW3l6nFHGTDkdXqGs9BSTvckUVIUV6o0x2Opl05gS4TrxiTYpVYK0a3ofib
nHJm5NEUs17nlq9n5u3zP49d0WEpoEseahRBBp7/coC/yc4M3JHnEHccW/zjZ2U0
khi8URKEGEx1aL1Uu8D3Xd8BLXOjDjZWn8A0hznRGQ==
-----END CERTIFICATE-----
Bag Attributes
    Trusted key usage (Oracle): <No Values>
subject=CN=secret-operator self-signed
issuer=CN=secret-operator self-signed
-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIDkvHj4cwRngwDQYJKoZIhvcNAQELBQAwJjEkMCIGA1UE
Awwbc2VjcmV0LW9wZXJhdG9yIHNlbGYtc2lnbmVkMB4XDTI1MDkwMzExMDI0MFoX
DTI1MDkwMzExMDg0MFowJjEkMCIGA1UEAwwbc2VjcmV0LW9wZXJhdG9yIHNlbGYt
c2lnbmVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp5EBsqaJItLd
3UtgC9bWv3VIprp3+FQPobQCMQpW7jne4gC11QxBuuIDN+LqlAZSfwt8UHy5B/LW
MUzgu+kfvXxZkYZsKmGNDi9GSH/fPkOV+rBDG6BOsXdQCmSPJZjCLuNWuysYfI3L
CQVoV0rG8H+APrX7N3vLosph3chYWgwb0teaKlqlGROVFiFISuMezSdyCkJbHkXB
Qjicj96FGa+jJX9zULJt07AWl2wsFbCL/+bDyOQs4LNQ+yQnhxXhepo4M9haLxrM
sd6JvmeCKNf17OSVe4a1rGc0hpZ+80AJ3D+cfMBoBPGkAk7njAI7HzpqNd/qFZo+
elfX3v4PQwIDAQABo00wSzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ3k3Wa
ZJsuVxSQaKZMFbmEviqTlzAJBgNVHSMEAjAAMA4GA1UdDwEB/wQEAwIBhjANBgkq
hkiG9w0BAQsFAAOCAQEAe851UwqPYYxKsCbOsIVqe9aamPOQ+70PNaEALWfkEpVS
kbJcsjw7m4wmG0m/Y4fTL+sdppYhShSPOV5vn09mW04hjOlaKRUyIGhkp9qaTIFh
bznnQ19zvnfHci8rs1LCIgjGL+iZ8aoUE8nyOeSbm1A8Yc0NcKw/WdC+MJ3jyFqe
hjfFpCCYu94nKhCQ5RhCfQBHmZ/IzwxTSDUUE3PoD2g4Rex9etISPY1CV5cJBjgv
VYIk9WlwUc6mepdY3CX/Oko6WEilm2y1zdKohGrsEnTeN6oG2l9XFdvqj71UBNop
iVAldveMLcVOv2D9jU48lYJFRagJc6wpCBOK0/Exjg==
-----END CERTIFICATE-----
        ";

        assert_eq!(
            split_pem_certificates(cli_output)
                .iter()
                .map(|bytes| String::from_utf8(bytes.to_vec())
                    .expect("PEM certificate is not valid utf-8"))
                .collect::<Vec<_>>(),
            vec![
                "-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIKt7H+4AWKFYwDQYJKoZIhvcNAQELBQAwJjEkMCIGA1UE
Awwbc2VjcmV0LW9wZXJhdG9yIHNlbGYtc2lnbmVkMB4XDTI1MDkwMzExMDIwMVoX
DTI1MDkwMzExMDgwMVowJjEkMCIGA1UEAwwbc2VjcmV0LW9wZXJhdG9yIHNlbGYt
c2lnbmVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviEC2WtidVLN
qU6BO8qQ3PPThYBfia6UbfU8y5k8qPKHOJhYjtCKPTqCD82ht/UgzoXJ4zzqKL9B
2cBid+zj3/fxSRDKaPBMQvthC13M6zOz5ig/Ry24iaIaiz5ASDuqaQ9Hw/Y7viPB
pxkypTR59tYHa4+1D8xPtQCUixpxgxfRPAehZibrlP8TZrb6wSEjuicXljh9pevn
jw/TxFcNZVHgDw2N6RqhgaurcS/i4ScWxELXrdqi1K6G2twcWw2SPiU3xujXAMG7
lGISeJJnecD/rHzMT13TYqmbu65tSrVfG9YRqbGqgMfk5faFzCoIZZ447OA2coE7
JA/CJ3djVQIDAQABo00wSzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ1LwpK
L93s9BJgZpJ6vRnX2SzzMzAJBgNVHSMEAjAAMA4GA1UdDwEB/wQEAwIBhjANBgkq
hkiG9w0BAQsFAAOCAQEADOrNsdHBc4qf8wJNmm2RIRaepJDxsMiCmEh9A7JLFZEb
IsOIbynhAvfHCCZqSDeRNaMdxjKax6STy6QDy/U5jrwAFS1/1yFR7zqGE9IDOmrs
5uxDCYU23p1fIjvr+Uz7lk/EwXVTtqjzLAp+NP4YIQNFWfdKv6me3F2Czz4yfTRj
sZ5ggeW3l6nFHGTDkdXqGs9BSTvckUVIUV6o0x2Opl05gS4TrxiTYpVYK0a3ofib
nHJm5NEUs17nlq9n5u3zP49d0WEpoEseahRBBp7/coC/yc4M3JHnEHccW/zjZ2U0
khi8URKEGEx1aL1Uu8D3Xd8BLXOjDjZWn8A0hznRGQ==
-----END CERTIFICATE-----",
                "-----BEGIN CERTIFICATE-----
MIIDGzCCAgOgAwIBAgIIDkvHj4cwRngwDQYJKoZIhvcNAQELBQAwJjEkMCIGA1UE
Awwbc2VjcmV0LW9wZXJhdG9yIHNlbGYtc2lnbmVkMB4XDTI1MDkwMzExMDI0MFoX
DTI1MDkwMzExMDg0MFowJjEkMCIGA1UEAwwbc2VjcmV0LW9wZXJhdG9yIHNlbGYt
c2lnbmVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp5EBsqaJItLd
3UtgC9bWv3VIprp3+FQPobQCMQpW7jne4gC11QxBuuIDN+LqlAZSfwt8UHy5B/LW
MUzgu+kfvXxZkYZsKmGNDi9GSH/fPkOV+rBDG6BOsXdQCmSPJZjCLuNWuysYfI3L
CQVoV0rG8H+APrX7N3vLosph3chYWgwb0teaKlqlGROVFiFISuMezSdyCkJbHkXB
Qjicj96FGa+jJX9zULJt07AWl2wsFbCL/+bDyOQs4LNQ+yQnhxXhepo4M9haLxrM
sd6JvmeCKNf17OSVe4a1rGc0hpZ+80AJ3D+cfMBoBPGkAk7njAI7HzpqNd/qFZo+
elfX3v4PQwIDAQABo00wSzAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQ3k3Wa
ZJsuVxSQaKZMFbmEviqTlzAJBgNVHSMEAjAAMA4GA1UdDwEB/wQEAwIBhjANBgkq
hkiG9w0BAQsFAAOCAQEAe851UwqPYYxKsCbOsIVqe9aamPOQ+70PNaEALWfkEpVS
kbJcsjw7m4wmG0m/Y4fTL+sdppYhShSPOV5vn09mW04hjOlaKRUyIGhkp9qaTIFh
bznnQ19zvnfHci8rs1LCIgjGL+iZ8aoUE8nyOeSbm1A8Yc0NcKw/WdC+MJ3jyFqe
hjfFpCCYu94nKhCQ5RhCfQBHmZ/IzwxTSDUUE3PoD2g4Rex9etISPY1CV5cJBjgv
VYIk9WlwUc6mepdY3CX/Oko6WEilm2y1zdKohGrsEnTeN6oG2l9XFdvqj71UBNop
iVAldveMLcVOv2D9jU48lYJFRagJc6wpCBOK0/Exjg==
-----END CERTIFICATE-----"
            ]
        );
    }
}
