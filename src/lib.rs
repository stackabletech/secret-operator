//! 
//! pure rust pkcs12 tool
//!
//!

use lazy_static::lazy_static;
use ring::digest::Digest;
use ring::hmac;
use ring::rand::{self, SecureRandom};
use yasna::{models::ObjectIdentifier, ASN1Error, ASN1ErrorKind, BERReader, DERWriter, Tag};

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
    static ref RAND: rand::SystemRandom = rand::SystemRandom::new();
}

const ITERATIONS: u64 = 2048;

fn sha1(bytes: &[u8]) -> Digest {
    use ring::digest::*;
    digest(&SHA1_FOR_LEGACY_USE_ONLY, bytes)
}

#[derive(Debug, Clone)]
pub struct EncryptedContentInfo {
    content_encryption_algorithm: AlgorithmIdentifier,
    encrypted_content: Vec<u8>,
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

    fn write(&self, w: DERWriter) {
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
                salt: salt,
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
    encrypted_content_info: EncryptedContentInfo,
}

impl EncryptedData {
    fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let version = r.next().read_u8()?;
            debug_assert_eq!(version, 0);

            let encrypted_content_info = EncryptedContentInfo::parse(r.next())?;
            Ok(EncryptedData {
                encrypted_content_info,
            })
        })
    }
    fn data(&self, password: &[u8]) -> Option<Vec<u8>> {
        self.encrypted_content_info.data(password)
    }
    fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_u8(0);
            self.encrypted_content_info.write(w.next());
        })
    }
    fn from_safe_bags(safe_bags: &[SafeBag], password: &[u8]) -> Option<Self> {
        let encrypted_content_info = EncryptedContentInfo::from_safe_bags(safe_bags, password)?;
        Some(EncryptedData {
            encrypted_content_info,
        })
    }
}

#[derive(Debug, Clone)]
pub enum ContentInfo {
    Data(Vec<u8>),
    EncryptedData(EncryptedData),
}

impl ContentInfo {
    fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        Ok(r.read_sequence(|r| {
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
            println!("undefined context type: {:?}", content_type);
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        })?)
    }
    pub fn data(&self, password: &[u8]) -> Option<Vec<u8>> {
        match self {
            ContentInfo::Data(data) => Some(data.to_owned()),
            ContentInfo::EncryptedData(encrypted) => encrypted.data(password),
        }
    }
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            ContentInfo::Data(_) => OID_DATA_CONTENT_TYPE.clone(),
            ContentInfo::EncryptedData(_) => OID_ENCRYPTED_DATA_CONTENT_TYPE.clone(),
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
    salt: Vec<u8>,
    iterations: u64,
}

impl Pkcs12PbeParams {
    fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let salt = r.next().read_bytes()?;
            let iterations = r.next().read_u64()?;
            Ok(Pkcs12PbeParams { salt, iterations })
        })
    }
    fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_bytes(&self.salt);
            w.next().write_u64(self.iterations);
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AlgorithmIdentifier {
    Sha1,
    PbewithSHAAnd40BitRC2CBC(Pkcs12PbeParams),
    PbeWithSHAAnd3KeyTripleDESCBC(Pkcs12PbeParams),
}

impl AlgorithmIdentifier {
    fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let oid = r.next().read_oid()?;

            if oid == *OID_SHA1 {
                r.next().read_null()?;
                return Ok(AlgorithmIdentifier::Sha1);
            }
            if oid == *OID_PBE_WITH_SHA1_AND40_BIT_RC2_CBC {
                let param = Pkcs12PbeParams::parse(r.next())?;
                return Ok(AlgorithmIdentifier::PbewithSHAAnd40BitRC2CBC(param));
            }
            if oid == *OID_PBE_WITH_SHA_AND3_KEY_TRIPLE_DESCBC {
                let param = Pkcs12PbeParams::parse(r.next())?;
                return Ok(AlgorithmIdentifier::PbeWithSHAAnd3KeyTripleDESCBC(param));
            }
            println!("unknown Algorithm Identifier : {}", oid);
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
        })
    }
    fn decrypt_pbe(&self, ciphertext: &[u8], password: &[u8]) -> Option<Vec<u8>> {
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
        }
    }
    fn write(&self, w: DERWriter) {
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
        })
    }
}

#[derive(Debug)]
pub struct DigestInfo {
    digest_algorithm: AlgorithmIdentifier,
    digest: Vec<u8>,
}

impl DigestInfo {
    fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let digest_algorithm = AlgorithmIdentifier::parse(r.next())?;
            let digest = r.next().read_bytes()?;
            Ok(DigestInfo {
                digest_algorithm,
                digest,
            })
        })
    }
    fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            self.digest_algorithm.write(w.next());
            w.next().write_bytes(&self.digest);
        })
    }
}

#[derive(Debug)]
pub struct MacData {
    mac: DigestInfo,
    salt: Vec<u8>,
    iterations: u32,
}

impl MacData {
    fn parse(r: BERReader) -> Result<MacData, ASN1Error> {
        Ok(r.read_sequence(|r| {
            let mac = DigestInfo::parse(r.next())?;
            let salt = r.next().read_bytes()?;
            let iterations = r.next().read_u32()?;
            Ok(MacData {
                mac,
                salt,
                iterations,
            })
        })?)
    }

    fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            self.mac.write(w.next());
            w.next().write_bytes(&self.salt);
            w.next().write_u32(self.iterations);
        })
    }

    fn verify_mac(&self, data: &[u8], password: &[u8]) -> bool {
        debug_assert_eq!(self.mac.digest_algorithm, AlgorithmIdentifier::Sha1);
        let key = pkcs12sha1(password, &self.salt, self.iterations as u64, 3, 20);
        let m = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key);
        hmac::verify(&m, data, &self.mac.digest).is_ok()
    }

    fn new(data: &[u8], password: &[u8]) -> MacData {
        let salt = rand().unwrap();
        let key = pkcs12sha1(password, &salt, ITERATIONS, 3, 20);
        let m = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &key);
        let digest = hmac::sign(&m, data).as_ref().to_owned();
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
    let rng = rand::SystemRandom::new();
    rng.fill(&mut buf).ok()?;
    Some(buf)
}

#[derive(Debug)]
pub struct PFX {
    version: u8,
    auth_safe: ContentInfo,
    mac_data: Option<MacData>,
}

impl PFX {
    pub fn new(
        cert_der: &[u8],
        key_der: &[u8],
        ca_der: Option<&[u8]>,
        password: &str,
        name: &str,
    ) -> Option<PFX> {
        let password = bmp_string(password);
        let salt = rand()?.to_vec();
        let encrypted_data =
            pbe_with_sha_and3_key_triple_des_cbc_encrypt(key_der, &password, &salt, ITERATIONS)?;
        let param = Pkcs12PbeParams {
            salt: salt,
            iterations: ITERATIONS,
        };
        let key_bag_inner = SafeBagKind::Pkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo {
            encryption_algorithm: AlgorithmIdentifier::PbeWithSHAAnd3KeyTripleDESCBC(param),
            encrypted_data,
        });
        let friendly_name = PKCS12Attribute::FriendlyName(name.to_owned());
        let local_key_id = PKCS12Attribute::LocalKeyId(sha1(cert_der).as_ref().to_owned());
        let key_bag = SafeBag {
            bag: key_bag_inner,
            attributes: vec![friendly_name.clone(), local_key_id.clone()],
        };
        let cert_bag_inner = SafeBagKind::CertBag(CertBag {
            cert: cert_der.to_owned(),
        });
        let cert_bag = SafeBag {
            bag: cert_bag_inner,
            attributes: vec![friendly_name, local_key_id],
        };
        let mut cert_bags = vec![cert_bag];
        if let Some(ca) = ca_der {
            cert_bags.push(SafeBag {
                bag: SafeBagKind::CertBag(CertBag {
                    cert: ca.to_owned(),
                }),
                attributes: vec![],
            });
        };
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
        Ok(yasna::parse_der(bytes, |r| {
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
        })?)
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
    pub fn cert_bags(&self, password: &str) -> Result<Vec<Vec<u8>>, ASN1Error> {
        let mut result = vec![];
        for safe_bag in self.bags(password)? {
            if let Some(cert) = safe_bag.bag.get_cert() {
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

#[allow(clippy::many_single_char_names)]
fn pkcs12sha1(pass: &[u8], salt: &[u8], iterations: u64, id: u8, size: u64) -> Vec<u8> {
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
    for i2 in 1..=c {
        let mut ai: Vec<u8> = d.iter().chain(i.iter()).cloned().collect();

        for _ in 0..r {
            ai = sha1(&ai).as_ref().to_owned();
        }

        a.append(&mut ai.clone());

        if i2 < c {
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
    }
    a.iter().take(size as usize).cloned().collect()
}

fn pbe_with_sha1_and40_bit_rc2_cbc(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
    use rc2::Rc2;
    type Rc2Cbc = Cbc<Rc2, Pkcs7>;

    let dk = pkcs12sha1(password, salt, iterations, 1, 5);
    let iv = pkcs12sha1(password, salt, iterations, 2, 8);

    let rc2 = Rc2Cbc::new_var(&dk, &iv).ok()?;
    rc2.decrypt_vec(data).ok()
}

fn pbe_with_sha1_and40_bit_rc2_cbc_encrypt(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
    use rc2::Rc2;
    type Rc2Cbc = Cbc<Rc2, Pkcs7>;

    let dk = pkcs12sha1(password, salt, iterations, 1, 5);
    let iv = pkcs12sha1(password, salt, iterations, 2, 8);

    let rc2 = Rc2Cbc::new_var(&dk, &iv).ok()?;
    Some(rc2.encrypt_vec(data))
}

fn pbe_with_sha_and3_key_triple_des_cbc(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
    use des::TdesEde3;
    type TDesCbc = Cbc<TdesEde3, Pkcs7>;

    let dk = pkcs12sha1(password, salt, iterations, 1, 24);
    let iv = pkcs12sha1(password, salt, iterations, 2, 8);

    let tdes = TDesCbc::new_var(&dk, &iv).ok()?;
    tdes.decrypt_vec(data).ok()
}

fn pbe_with_sha_and3_key_triple_des_cbc_encrypt(
    data: &[u8],
    password: &[u8],
    salt: &[u8],
    iterations: u64,
) -> Option<Vec<u8>> {
    use block_modes::{block_padding::Pkcs7, BlockMode, Cbc};
    use des::TdesEde3;
    type TDesCbc = Cbc<TdesEde3, Pkcs7>;

    let dk = pkcs12sha1(password, salt, iterations, 1, 24);
    let iv = pkcs12sha1(password, salt, iterations, 2, 8);

    let tdes = TDesCbc::new_var(&dk, &iv).ok()?;
    Some(tdes.encrypt_vec(data))
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
pub struct CertBag {
    cert: Vec<u8>, //x509 only
}

impl CertBag {
    pub fn parse(r: BERReader) -> Result<Self, ASN1Error> {
        r.read_sequence(|r| {
            let oid = r.next().read_oid()?;
            if oid != *OID_CERT_TYPE_X509_CERTIFICATE {
                println!("not x509 cert");
                return Err(ASN1Error::new(ASN1ErrorKind::Invalid));
            };
            let cert = r.next().read_tagged(Tag::context(0), |r| r.read_bytes())?;
            Ok(CertBag { cert })
        })
    }
    pub fn write(&self, w: DERWriter) {
        w.write_sequence(|w| {
            w.next().write_oid(&OID_CERT_TYPE_X509_CERTIFICATE);
            w.next()
                .write_tagged(Tag::context(0), |w| w.write_bytes(&self.cert))
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedPrivateKeyInfo {
    encryption_algorithm: AlgorithmIdentifier,
    encrypted_data: Vec<u8>,
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
    let epki2 = yasna::parse_ber(&der, |r| EncryptedPrivateKeyInfo::parse(r)).unwrap();
    assert_eq!(epki2, epki);
}

#[derive(Debug, Clone)]
pub enum SafeBagKind {
    //KeyBag(),
    Pkcs8ShroudedKeyBag(EncryptedPrivateKeyInfo),
    CertBag(CertBag),
    //CRLBag(),
    //SecretBag(),
    //SafeContents(Vec<SafeBag>),
}

impl SafeBagKind {
    pub fn parse(r: BERReader, oid: ObjectIdentifier) -> Result<Self, ASN1Error> {
        if oid == *OID_CERT_BAG {
            return Ok(SafeBagKind::CertBag(CertBag::parse(r)?));
        }
        if oid == *OID_PKCS8_SHROUDED_KEY_BAG {
            return Ok(SafeBagKind::Pkcs8ShroudedKeyBag(
                EncryptedPrivateKeyInfo::parse(r)?,
            ));
        }
        println!("unknown safe bug type : {}", oid);
        Err(ASN1Error::new(ASN1ErrorKind::Invalid))
    }
    pub fn write(&self, w: DERWriter) {
        match self {
            SafeBagKind::Pkcs8ShroudedKeyBag(epk) => epk.write(w),
            SafeBagKind::CertBag(cb) => cb.write(w),
        }
    }
    pub fn oid(&self) -> ObjectIdentifier {
        match self {
            SafeBagKind::Pkcs8ShroudedKeyBag(_) => OID_PKCS8_SHROUDED_KEY_BAG.clone(),
            SafeBagKind::CertBag(_) => OID_CERT_BAG.clone(),
        }
    }

    pub fn get_cert(&self) -> Option<Vec<u8>> {
        if let SafeBagKind::CertBag(cb) = self {
            return Some(cb.cert.to_owned());
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
pub enum PKCS12Attribute {
    FriendlyName(String),
    LocalKeyId(Vec<u8>),
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
            println!("unknown attribute : {}", oid);
            Err(ASN1Error::new(ASN1ErrorKind::Invalid))
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
                w.next().write_set_of(|w| w.next().write_bytes(&id))
            }
        })
    }
}
#[derive(Debug, Clone)]
pub struct SafeBag {
    bag: SafeBagKind,
    attributes: Vec<PKCS12Attribute>,
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
                .unwrap_or_else(|| vec![]);

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

    let certs = pfx.cert_bags("changeit").unwrap();
    assert_eq!(certs[0], cert);
    assert_eq!(certs[1], ca);
    assert!(pfx.verify_mac("changeit"));

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
fn test_pkcs12sha1() {
    use hex_literal::hex;
    let pass = bmp_string("");
    assert_eq!(pass, vec![0, 0]);
    let salt = hex!("9af4702958a8e95c");
    let iterations = 2048;
    let id = 1;
    let size = 24;
    let result = pkcs12sha1(&pass, &salt, iterations, id, size);
    let res = hex!("c2294aa6d02930eb5ce9c329eccb9aee1cb136baea746557");
    assert_eq!(result, res);
}

#[test]
fn test_pkcs12sha1_2() {
    use hex_literal::hex;
    let pass = bmp_string("");
    assert_eq!(pass, vec![0, 0]);
    let salt = hex!("9af4702958a8e95c");
    let iterations = 2048;
    let id = 2;
    let size = 8;
    let result = pkcs12sha1(&pass, &salt, iterations, id, size);
    let res = hex!("8e9f8fc7664378bc");
    assert_eq!(result, res);
}
