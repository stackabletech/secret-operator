//!
//! pure rust pkcs12 tool
//!
//!

use getrandom::getrandom;
use lazy_static::lazy_static;
use yasna::{models::ObjectIdentifier, ASN1Error, ASN1ErrorKind, BERReader, DERWriter, Tag};

use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};

type HmacSha1 = Hmac<Sha1>;

fn as_oid(s: &'static [u64]) -> ObjectIdentifier {
    ObjectIdentifier::from_slice(s)
}

lazy_static! {
    static ref OID_DATA_CONTENT_TYPE: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 7, 1]);
    static ref OID_ENCRYPTED_DATA_CONTENT_TYPE: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 7, 6]);
    static ref OID_FRIENDLY_NAME: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 9, 20]);
    static ref OID_LOCAL_KEY_ID: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 9, 21]);
    static ref OID_CERT_TYPE_X509_CERTIFICATE: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 9, 22, 1]);
    static ref OID_CERT_TYPE_SDSI_CERTIFICATE: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 9, 22, 2]);
    static ref OID_PBE_WITH_SHA_AND3_KEY_TRIPLE_DESCBC: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 1, 3]);
    static ref OID_SHA1: ObjectIdentifier = as_oid(&[1, 3, 14, 3, 2, 26]);
    static ref OID_PBE_WITH_SHA1_AND40_BIT_RC2_CBC: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 1, 6]);
    static ref OID_KEY_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 1]);
    static ref OID_PKCS8_SHROUDED_KEY_BAG: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 2]);
    static ref OID_CERT_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 3]);
    static ref OID_CRL_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 4]);
    static ref OID_SECRET_BAG: ObjectIdentifier = as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 5]);
    static ref OID_SAFE_CONTENTS_BAG: ObjectIdentifier =
        as_oid(&[1, 2, 840, 113_549, 1, 12, 10, 1, 6]);
}

const ITERATIONS: u64 = 2048;

fn sha1(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

#[derive(Debug, Clone)]
pub struct EncryptedContentInfo {
    pub content_encryption_algorithm: AlgorithmIdentifier,
    pub encrypted_content: Vec<u8>,
}

impl EncryptedContentInfo {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let content_type = r.next().read_oid()?;
            debug_assert_eq!(content_type, *OID_DATA_CONTENT_TYPE);
            let content_encryption_algorithm = AlgorithmIdentifier::parse(r.next())?;
            let encrypted_content = r
                .next()
                .read_tagged_implicit(Tag::context(0), |r| r.read_bytes())?;
            Ok(EncryptedContentInfo {
                content_encryption_algorithm,
                encrypted_content,
            })
        })
    }

    pub fn data(&self, password: &[u8]) -> Option<Vec<u8>> {
        self.content_encryption_algorithm
            .decrypt_pbe(&self.encrypted_content, password)
    }

    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_oid(&OID_DATA_CONTENT_TYPE);
            self.content_encryption_algorithm.write(w.next());
            w.next()
                .write_tagged_implicit(Tag::context(0), |w| w.write_bytes(&self.encrypted_content));
        })
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|w| self.write(w))
    }

    pub fn from_safe_bags(safe_bags: &[SafeBag], password: &[u8]) -> Option<EncryptedContentInfo> {
        let data = yasna::construct_der(|w| {
            w.write_sequence_of(|w| {
                for sb in safe_bags {
                    sb.write(w.next());
                }
            })
        });
        let salt = rand()?.to_vec();
        let encrypted_content =
            pbe_with_sha1_and40_bit_rc2_cbc_encrypt(&data, password, &salt, ITERATIONS)?;
        let content_encryption_algorithm =
            AlgorithmIdentifier::PbewithSHAAnd40BitRC2CBC(Pkcs12PbeParams {
                salt,
                iterations: ITERATIONS,
            });
        Some(EncryptedContentInfo {
            content_encryption_algorithm,
            encrypted_content,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedData {
    pub encrypted_content_info: EncryptedContentInfo,
}

impl EncryptedData {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let version = r.next().read_u8()?;
            debug_assert_eq!(version, 0);

            let encrypted_content_info = EncryptedContentInfo::parse(r.next())?;
            Ok(EncryptedData {
                encrypted_content_info,
            })
        })
    }
    pub fn data(&self, password: &[u8]) -> Option<Vec<u8>> {
        self.encrypted_content_info.data(password)
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            self.encrypted_content_info.write(w.next());
        })
    }
    pub fn from_safe_bags(safe_bags: &[SafeBag], password: &[u8]) -> Option<Self> {
        let encrypted_content_info = EncryptedContentInfo::from_safe_bags(safe_bags, password)?;
        Some(EncryptedData {
            encrypted_content_info,
        })
    }
}

#[derive(Debug, Clone)]
pub struct OtherContext {
    pub content_type: ObjectIdentifier,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ContentInfo {
    Data(Vec<u8>),
    EncryptedData(EncryptedData),
    OtherContext(OtherContext),
}

impl ContentInfo {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let content_type = r.next().read_oid()?;
            if content_type == *OID_DATA_CONTENT_TYPE {
                let data = r.next().read_tagged(Tag::context(0), |r| r.read_bytes())?;
                return Ok(ContentInfo::Data(data));
            }
            if content_type == *OID_ENCRYPTED_DATA_CONTENT_TYPE {
                let result = r.next().read_tagged(Tag::context(0), |r| {
                    Ok(ContentInfo::EncryptedData(EncryptedData::parse(r)?))
                });
                return result;
            }

            let content = r.next().read_tagged(Tag::context(0), |r| r.read_der())?;
            Ok(ContentInfo::OtherContext(OtherContext {
                content_type,
                content,
            }))
        })
    }
    pub fn data(&self, password: &[u8]) -> Option<Vec<u8>> {
        match self {
            ContentInfo::Data(data) => Some(data.to_owned()),
            ContentInfo::EncryptedData(encrypted) => encrypted.data(password),
            ContentInfo::OtherContext(_) => None,
        }
    }
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            ContentInfo::Data(_) => OID_DATA_CONTENT_TYPE.clone(),
            ContentInfo::EncryptedData(_) => OID_ENCRYPTED_DATA_CONTENT_TYPE.clone(),
            ContentInfo::OtherContext(other) => other.content_type.clone(),
        }
    }
    pub fn write(&self, w: DERWriter) {
        match self {
            ContentInfo::Data(data) => w.write_sequence(|w| {
                w.next().write_oid(&OID_DATA_CONTENT_TYPE);
                w.next()
                    .write_tagged(Tag::context(0), |w| w.write_bytes(data))
            }),
            ContentInfo::EncryptedData(encrypted_data) => w.write_sequence(|w| {
                w.next().write_oid(&OID_ENCRYPTED_DATA_CONTENT_TYPE);
                w.next()
                    .write_tagged(Tag::context(0), |w| encrypted_data.write(w))
            }),
            ContentInfo::OtherContext(other) => w.write_sequence(|w| {
                w.next().write_oid(&other.content_type);
                w.next()
                    .write_tagged(Tag::context(0), |w| w.write_der(&other.content))
            }),
        }
    }
    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|w| self.write(w))
    }

    pub fn from_der(der: &[u8]) -> Result<Self, ASN1Error> {
        yasna::parse_der(der, Self::parse)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pkcs12PbeParams {
    pub salt: Vec<u8>,
    pub iterations: u64,
}

impl Pkcs12PbeParams {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let salt = r.next().read_bytes()?;
            let iterations = r.next().read_u64()?;
            Ok(Pkcs12PbeParams { salt, iterations })
        })
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_bytes(&self.salt);
            w.next().write_u64(self.iterations);
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OtherAlgorithmIdentifier {
    pub algorithm_type: ObjectIdentifier,
    pub params: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlgorithmIdentifier {
    Sha1,
    PbewithSHAAnd40BitRC2CBC(Pkcs12PbeParams),
    PbeWithSHAAnd3KeyTripleDESCBC(Pkcs12PbeParams),
    OtherAlg(OtherAlgorithmIdentifier),
}

impl AlgorithmIdentifier {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let algorithm_type = r.next().read_oid()?;
            if algorithm_type == *OID_SHA1 {
                r.read_optional(|r| r.read_null())?;
                return Ok(AlgorithmIdentifier::Sha1);
            }
            if algorithm_type == *OID_PBE_WITH_SHA1_AND40_BIT_RC2_CBC {
                let params = Pkcs12PbeParams::parse(r.next())?;
                return Ok(AlgorithmIdentifier::PbewithSHAAnd40BitRC2CBC(params));
            }
            if algorithm_type == *OID_PBE_WITH_SHA_AND3_KEY_TRIPLE_DESCBC {
                let params = Pkcs12PbeParams::parse(r.next())?;
                return Ok(AlgorithmIdentifier::PbeWithSHAAnd3KeyTripleDESCBC(params));
            }
            let params = r.read_optional(|r| r.read_der())?;
            Ok(AlgorithmIdentifier::OtherAlg(OtherAlgorithmIdentifier {
                algorithm_type,
                params,
            }))
        })
    }
    pub fn decrypt_pbe(&self, ciphertext: &[u8], password: &[u8]) -> Option<Vec<u8>> {
        match self {
            AlgorithmIdentifier::Sha1 => None,
            AlgorithmIdentifier::PbewithSHAAnd40BitRC2CBC(param) => {
                pbe_with_sha1_and40_bit_rc2_cbc(ciphertext, password, &param.salt, param.iterations)
            }
            AlgorithmIdentifier::PbeWithSHAAnd3KeyTripleDESCBC(param) => {
                pbe_with_sha_and3_key_triple_des_cbc(
                    ciphertext,
                    password,
                    &param.salt,
                    param.iterations,
                )
            }
            AlgorithmIdentifier::OtherAlg(_) => None,
        }
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| match self {
            AlgorithmIdentifier::Sha1 => {
                w.next().write_oid(&OID_SHA1);
                w.next().write_null();
            }
            AlgorithmIdentifier::PbewithSHAAnd40BitRC2CBC(p) => {
                w.next().write_oid(&OID_PBE_WITH_SHA1_AND40_BIT_RC2_CBC);
                p.write(w.next());
            }
            AlgorithmIdentifier::PbeWithSHAAnd3KeyTripleDESCBC(p) => {
                w.next().write_oid(&OID_PBE_WITH_SHA_AND3_KEY_TRIPLE_DESCBC);
                p.write(w.next());
            }
            AlgorithmIdentifier::OtherAlg(other) => {
                w.next().write_oid(&other.algorithm_type);
                if let Some(der) = &other.params {
                    w.next().write_der(der);
                }
            }
        })
    }
}

#[derive(Debug)]
pub struct DigestInfo {
    pub digest_algorithm: AlgorithmIdentifier,
    pub digest: Vec<u8>,
}

impl DigestInfo {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let digest_algorithm = AlgorithmIdentifier::parse(r.next())?;
            let digest = r.next().read_bytes()?;
            Ok(DigestInfo {
                digest_algorithm,
                digest,
            })
        })
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            self.digest_algorithm.write(w.next());
            w.next().write_bytes(&self.digest);
        })
    }
}

#[derive(Debug)]
pub struct MacData {
    pub mac: DigestInfo,
    pub salt: Vec<u8>,
    pub iterations: u32,
}

impl MacData {
    pub fn parse(r: BERReader) -> Result<MacData, ASN1Error> {
        r.read_sequence(|r| {
            let mac = DigestInfo::parse(r.next())?;
            let salt = r.next().read_bytes()?;
            let iterations = r.next().read_u32()?;
            Ok(MacData {
                mac,
                salt,
                iterations,
            })
        })
    }

    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            self.mac.write(w.next());
            w.next().write_bytes(&self.salt);
            w.next().write_u32(self.iterations);
        })
    }

    pub fn verify_mac(&self, data: &[u8], password: &[u8]) -> bool {
        debug_assert_eq!(self.mac.digest_algorithm, AlgorithmIdentifier::Sha1);
        let key = pbepkcs12sha1(password, &self.salt, self.iterations as u64, 3, 20);
        let mut mac = HmacSha1::new_from_slice(&key).unwrap();
        mac.update(data);
        mac.verify_slice(&self.mac.digest).is_ok()
    }

    pub fn new(data: &[u8], password: &[u8]) -> MacData {
        let salt = rand().unwrap();
        let key = pbepkcs12sha1(password, &salt, ITERATIONS, 3, 20);
        let mut mac = HmacSha1::new_from_slice(&key).unwrap();
        mac.update(data);
        let digest = mac.finalize().into_bytes().to_vec();
        MacData {
            mac: DigestInfo {
                digest_algorithm: AlgorithmIdentifier::Sha1,
                digest,
            },
            salt: salt.to_vec(),
            iterations: ITERATIONS as u32,
        }
    }
}

fn rand() -> Option<[u8; 8]> {
    let mut buf = [0u8; 8];
    if getrandom(&mut buf).is_ok() {
        Some(buf)
    } else {
        None
    }
}

#[derive(Debug)]
pub struct PFX {
    pub version: u8,
    pub auth_safe: ContentInfo,
    pub mac_data: Option<MacData>,
}

impl PFX {
    pub fn new(
        cert_der: &[u8],
        key_der: &[u8],
        ca_der: Option<&[u8]>,
        password: &str,
        name: &str,
    ) -> Option<PFX> {
        let mut cas = vec![];
        if let Some(ca) = ca_der {
            cas.push(ca);
        }
        Self::new_with_cas(cert_der, key_der, &cas, password, name)
    }
    pub fn new_with_cas(
        cert_der: &[u8],
        key_der: &[u8],
        ca_der_list: &[&[u8]],
        password: &str,
        name: &str,
    ) -> Option<PFX> {
        let password = bmp_string(password);
        let salt = rand()?.to_vec();
        let encrypted_data =
            pbe_with_sha_and3_key_triple_des_cbc_encrypt(key_der, &password, &salt, ITERATIONS)?;
        let param = Pkcs12PbeParams {
            salt,
            iterations: ITERATIONS,
        };
        let key_bag_inner = SafeBagKind::Pkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo {
            encryption_algorithm: AlgorithmIdentifier::PbeWithSHAAnd3KeyTripleDESCBC(param),
            encrypted_data,
        });
        let friendly_name = PKCS12Attribute::FriendlyName(name.to_owned());
        let local_key_id = PKCS12Attribute::LocalKeyId(sha1(cert_der));
        let key_bag = SafeBag {
            bag: key_bag_inner,
            attributes: vec![friendly_name.clone(), local_key_id.clone()],
        };
        let cert_bag_inner = SafeBagKind::CertBag(CertBag::X509(cert_der.to_owned()));
        let cert_bag = SafeBag {
            bag: cert_bag_inner,
            attributes: vec![friendly_name, local_key_id],
        };
        let mut cert_bags = vec![cert_bag];
        for ca in ca_der_list {
            cert_bags.push(SafeBag {
                bag: SafeBagKind::CertBag(CertBag::X509((*ca).to_owned())),
                attributes: vec![],
            });
        }
        let contents = yasna::construct_der(|w| {
            w.write_sequence_of(|w| {
                ContentInfo::EncryptedData(
                    EncryptedData::from_safe_bags(&cert_bags, &password)
                        .ok_or_else(|| ASN1Error::new(ASN1ErrorKind::Invalid))
                        .unwrap(),
                )
                .write(w.next());
                ContentInfo::Data(yasna::construct_der(|w| {
                    w.write_sequence_of(|w| {
                        key_bag.write(w.next());
                    })
                }))
                .write(w.next());
            });
        });
        let mac_data = MacData::new(&contents, &password);
        Some(PFX {
            version: 3,
            auth_safe: ContentInfo::Data(contents),
            mac_data: Some(mac_data),
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<PFX, ASN1Error> {
        yasna::parse_der(bytes, |r| {
            r.read_sequence(|r| {
                let version = r.next().read_u8()?;
                let auth_safe = ContentInfo::parse(r.next())?;
                let mac_data = r.read_optional(MacData::parse)?;
                Ok(PFX {
                    version,
                    auth_safe,
                    mac_data,
                })
            })
        })
    }

    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_u8(self.version);
            self.auth_safe.write(w.next());
            if let Some(mac_data) = &self.mac_data {
                mac_data.write(w.next())
            }
        })
    }

    pub fn to_der(&self) -> Vec<u8> {
        yasna::construct_der(|w| self.write(w))
    }
    pub fn bags(&self, password: &str) -> Result<Vec<SafeBag>, ASN1Error> {
        let password = bmp_string(password);

        let data = self
            .auth_safe
            .data(&password)
            .ok_or_else(|| ASN1Error::new(ASN1ErrorKind::Invalid))?;

        let contents = yasna::parse_der(&data, |r| r.collect_sequence_of(ContentInfo::parse))?;

        let mut result = vec![];
        for content in contents.iter() {
            let data = content
                .data(&password)
                .ok_or_else(|| ASN1Error::new(ASN1ErrorKind::Invalid))?;

            let safe_bags = yasna::parse_der(&data, |r| r.collect_sequence_of(SafeBag::parse))?;

            for safe_bag in safe_bags.iter() {
                result.push(safe_bag.to_owned())
            }
        }
        Ok(result)
    }
    //DER-encoded X.509 certificate
    pub fn cert_bags(&self, password: &str) -> Result<Vec<Vec<u8>>, ASN1Error> {
        self.cert_x509_bags(password)
    }
    //DER-encoded X.509 certificate
    pub fn cert_x509_bags(&self, password: &str) -> Result<Vec<Vec<u8>>, ASN1Error> {
        let mut result = vec![];
        for safe_bag in self.bags(password)? {
            if let Some(cert) = safe_bag.bag.get_x509_cert() {
                result.push(cert);
            }
        }
        Ok(result)
    }
    pub fn cert_sdsi_bags(&self, password: &str) -> Result<Vec<String>, ASN1Error> {
        let mut result = vec![];
        for safe_bag in self.bags(password)? {
            if let Some(cert) = safe_bag.bag.get_sdsi_cert() {
                result.push(cert);
            }
        }
        Ok(result)
    }
    pub fn key_bags(&self, password: &str) -> Result<Vec<Vec<u8>>, ASN1Error> {
        let bmp_password = bmp_string(password);
        let mut result = vec![];
        for safe_bag in self.bags(password)? {
            if let Some(key) = safe_bag.bag.get_key(&bmp_password) {
                result.push(key);
            }
        }
        Ok(result)
    }

    pub fn verify_mac(&self, password: &str) -> bool {
        let bmp_password = bmp_string(password);
        if let Some(mac_data) = &self.mac_data {
            return match self.auth_safe.data(&bmp_password) {
                Some(data) => mac_data.verify_mac(&data, &bmp_password),
                None => false,
            };
        }
        true
    }
}

#[inline(always)]
fn pbepkcs12sha1core(d: &[u8], i: &[u8], a: &mut Vec<u8>, iterations: u64) -> Vec<u8> {
    let mut ai: Vec<u8> = d.iter().chain(i.iter()).cloned().collect();
    for _ in 0..iterations {
        ai = sha1(&ai);
    }
    a.append(&mut ai.clone());
    ai
}

#[allow(clippy::many_single_char_names)]
fn pbepkcs12sha1(pass: &[u8], salt: &[u8], iterations: u64, id: u8, size: u64) -> Vec<u8> {
    const U: u64 = 160 / 8;
    const V: u64 = 512 / 8;
    let r: u64 = iterations;
    let d = [id; V as usize];
    fn get_len(s: usize) -> usize {
        let s = s as u64;
        (V * ((s + V - 1) / V)) as usize
    }
    let s = salt.iter().cycle().take(get_len(salt.len()));
    let p = pass.iter().cycle().take(get_len(pass.len()));
    let mut i: Vec<u8> = s.chain(p).cloned().collect();
    let c = (size + U - 1) / U;
    let mut a: Vec<u8> = vec![];
    for _ in 1..c {
        let ai = pbepkcs12sha1core(&d, &i, &mut a, r);

        let b: Vec<u8> = ai.iter().cycle().take(V as usize).cloned().collect();

        let b_iter = b.iter().rev().cycle().take(i.len());
        let i_b_iter = i.iter_mut().rev().zip(b_iter);
        let mut inc = 1u8;
        for (i3, (ii, bi)) in i_b_iter.enumerate() {
            if ((i3 as u64) % V) == 0 {
                inc = 1;
            }
            let (ii2, inc2) = ii.overflowing_add(*bi);
            let (ii3, inc3) = ii2.overflowing_add(inc);
            inc = (inc2 || inc3) as u8;
            *ii = ii3;
        }
    }

    pbepkcs12sha1core(&d, &i, &mut a, r);

    a.iter().take(size as usize).cloned().collect()
}

fn pbe_with_sha1_and40_bit_rc2_cbc(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use cbc::{
        cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit},
        Decryptor,
    };
    use rc2::Rc2;
    type Rc2Cbc = Decryptor<Rc2>;

    let dk = pbepkcs12sha1(password, salt, iterations, 1, 5);
    let iv = pbepkcs12sha1(password, salt, iterations, 2, 8);

    let rc2 = Rc2Cbc::new_from_slices(&dk, &iv).ok()?;
    rc2.decrypt_padded_vec_mut::<Pkcs7>(data).ok()
}

fn pbe_with_sha1_and40_bit_rc2_cbc_encrypt(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use cbc::{
        cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
        Encryptor,
    };
    use rc2::Rc2;
    type Rc2Cbc = Encryptor<Rc2>;

    let dk = pbepkcs12sha1(password, salt, iterations, 1, 5);
    let iv = pbepkcs12sha1(password, salt, iterations, 2, 8);

    let rc2 = Rc2Cbc::new_from_slices(&dk, &iv).ok()?;
    Some(rc2.encrypt_padded_vec_mut::<Pkcs7>(data))
}

fn pbe_with_sha_and3_key_triple_des_cbc(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use cbc::{
        cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit},
        Decryptor,
    };
    use des::TdesEde3;
    type TDesCbc = Decryptor<TdesEde3>;

    let dk = pbepkcs12sha1(password, salt, iterations, 1, 24);
    let iv = pbepkcs12sha1(password, salt, iterations, 2, 8);

    let tdes = TDesCbc::new_from_slices(&dk, &iv).ok()?;
    tdes.decrypt_padded_vec_mut::<Pkcs7>(data).ok()
}

fn pbe_with_sha_and3_key_triple_des_cbc_encrypt(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use cbc::{
        cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit},
        Encryptor,
    };
    use des::TdesEde3;
    type TDesCbc = Encryptor<TdesEde3>;

    let dk = pbepkcs12sha1(password, salt, iterations, 1, 24);
    let iv = pbepkcs12sha1(password, salt, iterations, 2, 8);

    let tdes = TDesCbc::new_from_slices(&dk, &iv).ok()?;
    Some(tdes.encrypt_padded_vec_mut::<Pkcs7>(data))
}

fn bmp_string(s: &str) -> Vec<u8> {
    let utf16: Vec<u16> = s.encode_utf16().collect();

    let mut bytes = Vec::with_capacity(utf16.len() * 2 + 2);
    for c in utf16 {
        bytes.push((c / 256) as u8);
        bytes.push((c % 256) as u8);
    }
    bytes.push(0x00);
    bytes.push(0x00);
    bytes
}

#[derive(Debug, Clone)]
pub enum CertBag {
    X509(Vec<u8>),
    SDSI(String),
}

impl CertBag {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let oid = r.next().read_oid()?;
            if oid == *OID_CERT_TYPE_X509_CERTIFICATE {
                let x509 = r.next().read_tagged(Tag::context(0), |r| r.read_bytes())?;
                return Ok(CertBag::X509(x509));
            };
            if oid == *OID_CERT_TYPE_SDSI_CERTIFICATE {
                let sdsi = r
                    .next()
                    .read_tagged(Tag::context(0), |r| r.read_ia5_string())?;
                return Ok(CertBag::SDSI(sdsi));
            }
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        })
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| match self {
            CertBag::X509(x509) => {
                w.next().write_oid(&OID_CERT_TYPE_X509_CERTIFICATE);
                w.next()
                    .write_tagged(Tag::context(0), |w| w.write_bytes(x509));
            }
            CertBag::SDSI(sdsi) => {
                w.next().write_oid(&OID_CERT_TYPE_SDSI_CERTIFICATE);
                w.next()
                    .write_tagged(Tag::context(0), |w| w.write_ia5_string(sdsi));
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedPrivateKeyInfo {
    pub encryption_algorithm: AlgorithmIdentifier,
    pub encrypted_data: Vec<u8>,
}

impl EncryptedPrivateKeyInfo {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let encryption_algorithm = AlgorithmIdentifier::parse(r.next())?;

            let encrypted_data = r.next().read_bytes()?;

            Ok(EncryptedPrivateKeyInfo {
                encryption_algorithm,
                encrypted_data,
            })
        })
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            self.encryption_algorithm.write(w.next());
            w.next().write_bytes(&self.encrypted_data);
        })
    }
    pub fn decrypt(&self, password: &[u8]) -> Option<Vec<u8>> {
        self.encryption_algorithm
            .decrypt_pbe(&self.encrypted_data, password)
    }
}

#[test]
fn test_encrypted_private_key_info() {
    let epki = EncryptedPrivateKeyInfo {
        encryption_algorithm: AlgorithmIdentifier::Sha1,
        encrypted_data: b"foo".to_vec(),
    };
    let der = yasna::construct_der(|w| {
        epki.write(w);
    });
    let epki2 = yasna::parse_ber(&der, EncryptedPrivateKeyInfo::parse).unwrap();
    assert_eq!(epki2, epki);
}

#[derive(Debug, Clone)]
pub struct OtherBag {
    pub bag_id: ObjectIdentifier,
    pub bag_value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum SafeBagKind {
    //KeyBag(),
    Pkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo),
    CertBag(CertBag),
    //CRLBag(),
    //SecretBag(),
    //SafeContents(Vec<SafeBag>),
    OtherBagKind(OtherBag),
}

impl SafeBagKind {
    pub fn parse(r: BERReader, bag_id: ObjectIdentifier) -> Result<Self, ASN1Error> {
        if bag_id == *OID_CERT_BAG {
            return Ok(SafeBagKind::CertBag(CertBag::parse(r)?));
        }
        if bag_id == *OID_PKCS8_SHROUDED_KEY_BAG {
            return Ok(SafeBagKind::Pkcs8ShroudedKeyBag(
                EncryptedPrivateKeyInfo::parse(r)?,
            ));
        }
        let bag_value = r.read_der()?;
        Ok(SafeBagKind::OtherBagKind(OtherBag { bag_id, bag_value }))
    }
    pub fn write(&self, w: DERWriter) {
        match self {
            SafeBagKind::Pkcs8ShroudedKeyBag(epk) => epk.write(w),
            SafeBagKind::CertBag(cb) => cb.write(w),
            SafeBagKind::OtherBagKind(other) => w.write_der(&other.bag_value),
        }
    }
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            SafeBagKind::Pkcs8ShroudedKeyBag(_) => OID_PKCS8_SHROUDED_KEY_BAG.clone(),
            SafeBagKind::CertBag(_) => OID_CERT_BAG.clone(),
            SafeBagKind::OtherBagKind(other) => other.bag_id.clone(),
        }
    }
    pub fn get_x509_cert(&self) -> Option<Vec<u8>> {
        if let SafeBagKind::CertBag(CertBag::X509(x509)) = self {
            return Some(x509.to_owned());
        }
        None
    }

    pub fn get_sdsi_cert(&self) -> Option<String> {
        if let SafeBagKind::CertBag(CertBag::SDSI(sdsi)) = self {
            return Some(sdsi.to_owned());
        }
        None
    }

    pub fn get_key(&self, password: &[u8]) -> Option<Vec<u8>> {
        if let SafeBagKind::Pkcs8ShroudedKeyBag(kb) = self {
            return kb.decrypt(password);
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct OtherAttribute {
    pub oid: ObjectIdentifier,
    pub data: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub enum PKCS12Attribute {
    FriendlyName(String),
    LocalKeyId(Vec<u8>),
    Other(OtherAttribute),
}

impl PKCS12Attribute {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let oid = r.next().read_oid()?;
            if oid == *OID_FRIENDLY_NAME {
                let name = r
                    .next()
                    .collect_set_of(|s| s.read_bmp_string())?
                    .pop()
                    .ok_or_else(|| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                return Ok(PKCS12Attribute::FriendlyName(name));
            }
            if oid == *OID_LOCAL_KEY_ID {
                let local_key_id = r
                    .next()
                    .collect_set_of(|s| s.read_bytes())?
                    .pop()
                    .ok_or_else(|| ASN1Error::new(ASN1ErrorKind::Invalid))?;
                return Ok(PKCS12Attribute::LocalKeyId(local_key_id));
            }

            let data = r.next().collect_set_of(|s| s.read_der())?;
            let other = OtherAttribute { oid, data };
            Ok(PKCS12Attribute::Other(other))
        })
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| match self {
            PKCS12Attribute::FriendlyName(name) => {
                w.next().write_oid(&OID_FRIENDLY_NAME);
                w.next().write_set_of(|w| {
                    w.next().write_bmp_string(name);
                })
            }
            PKCS12Attribute::LocalKeyId(id) => {
                w.next().write_oid(&OID_LOCAL_KEY_ID);
                w.next().write_set_of(|w| w.next().write_bytes(id))
            }
            PKCS12Attribute::Other(other) => {
                w.next().write_oid(&other.oid);
                w.next().write_set_of(|w| {
                    for bytes in other.data.iter() {
                        w.next().write_der(bytes);
                    }
                })
            }
        })
    }
}
#[derive(Debug, Clone)]
pub struct SafeBag {
    pub bag: SafeBagKind,
    pub attributes: Vec<PKCS12Attribute>,
}

impl SafeBag {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let oid = r.next().read_oid()?;

            let bag = r
                .next()
                .read_tagged(Tag::context(0), |r| SafeBagKind::parse(r, oid))?;

            let attributes = r
                .read_optional(|r| r.collect_set_of(PKCS12Attribute::parse))?
                .unwrap_or_else(Vec::new);

            Ok(SafeBag { bag, attributes })
        })
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_oid(&self.bag.oid());
            w.next()
                .write_tagged(Tag::context(0), |w| self.bag.write(w));
            if !self.attributes.is_empty() {
                w.next().write_set_of(|w| {
                    for attr in &self.attributes {
                        attr.write(w.next());
                    }
                })
            }
        })
    }
    pub fn friendly_name(&self) -> Option<String> {
        for attr in self.attributes.iter() {
            if let PKCS12Attribute::FriendlyName(name) = attr {
                return Some(name.to_owned());
            }
        }
        None
    }
    pub fn local_key_id(&self) -> Option<Vec<u8>> {
        for attr in self.attributes.iter() {
            if let PKCS12Attribute::LocalKeyId(id) = attr {
                return Some(id.to_owned());
            }
        }
        None
    }
}

#[test]
fn test_create_p12() {
    use std::fs::File;
    use std::io::{Read, Write};
    let mut cafile = File::open("ca.der").unwrap();
    let mut ca = vec![];
    cafile.read_to_end(&mut ca).unwrap();
    let mut fcert = File::open("clientcert.der").unwrap();
    let mut fkey = File::open("clientkey.der").unwrap();
    let mut cert = vec![];
    fcert.read_to_end(&mut cert).unwrap();
    let mut key = vec![];
    fkey.read_to_end(&mut key).unwrap();
    let p12 = PFX::new(&cert, &key, Some(&ca), "changeit", "look")
        .unwrap()
        .to_der();

    let pfx = PFX::parse(&p12).unwrap();

    let keys = pfx.key_bags("changeit").unwrap();
    assert_eq!(keys[0], key);

    let certs = pfx.cert_x509_bags("changeit").unwrap();
    assert_eq!(certs[0], cert);
    assert_eq!(certs[1], ca);
    assert!(pfx.verify_mac("changeit"));

    let mut fp12 = File::create("test.p12").unwrap();
    fp12.write_all(&p12).unwrap();
}
#[test]
fn test_create_p12_without_password() {
    use std::fs::File;
    use std::io::{Read, Write};
    let mut cafile = File::open("ca.der").unwrap();
    let mut ca = vec![];
    cafile.read_to_end(&mut ca).unwrap();
    let mut fcert = File::open("clientcert.der").unwrap();

    let mut cert = vec![];
    fcert.read_to_end(&mut cert).unwrap();

    let p12 = PFX::new(&cert, &[], Some(&ca), "", "look")
        .unwrap()
        .to_der();

    let pfx = PFX::parse(&p12).unwrap();

    let certs = pfx.cert_x509_bags("").unwrap();
    assert_eq!(certs[0], cert);
    assert_eq!(certs[1], ca);
    assert!(pfx.verify_mac(""));

    let mut fp12 = File::create("test.p12").unwrap();
    fp12.write_all(&p12).unwrap();
}

#[test]
fn test_bmp_string() {
    let value = bmp_string("Beavis");
    assert!(
        value
            == [0x00, 0x42, 0x00, 0x65, 0x00, 0x61, 0x00, 0x76, 0x00, 0x69, 0x00, 0x73, 0x00, 0x00]
    )
}

#[test]
fn test_pbepkcs12sha1() {
    use hex_literal::hex;
    let pass = bmp_string("");
    assert_eq!(pass, vec![0, 0]);
    let salt = hex!("9af4702958a8e95c");
    let iterations = 2048;
    let id = 1;
    let size = 24;
    let result = pbepkcs12sha1(&pass, &salt, iterations, id, size);
    let res = hex!("c2294aa6d02930eb5ce9c329eccb9aee1cb136baea746557");
    assert_eq!(result, res);
}

#[test]
fn test_pbepkcs12sha1_2() {
    use hex_literal::hex;
    let pass = bmp_string("");
    assert_eq!(pass, vec![0, 0]);
    let salt = hex!("9af4702958a8e95c");
    let iterations = 2048;
    let id = 2;
    let size = 8;
    let result = pbepkcs12sha1(&pass, &salt, iterations, id, size);
    let res = hex!("8e9f8fc7664378bc");
    assert_eq!(result, res);
}
