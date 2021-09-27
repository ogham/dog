//! ECH RFC draft 13 section 4

use core::fmt;
use std::{
    convert::TryInto,
    io::{self, Read},
};

use byteorder::{BigEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};

#[macro_use]
mod macros;
mod cursor_ext;
mod serde_with_base64;

use cursor_ext::{CursorExt, Opaque, ReadFromCursor};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ECHConfigList {
    configs: Vec<ECHConfig>,
}

impl ECHConfigList {
    pub fn from_base64(base: &str) -> io::Result<Self> {
        let buffer = base64::decode_config(base, base64::STANDARD)
            .map_err(|de| io::Error::new(io::ErrorKind::Other, format!("{}", de)))?;
        log::trace!("{:?}", buffer);

        let mut cursor = io::Cursor::new(&buffer[..]);
        let ret = Self::read_from(&mut cursor)?;
        let remain = cursor.std_remaining_slice();
        if remain.is_empty() {
            Ok(ret)
        } else {
            println!("parsed but had bytes leftover: {:?}", ret);
            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("base64 string had leftover bytes: {:?}", remain),
            ))
        }
    }
}

impl From<Vec<ECHConfig>> for ECHConfigList {
    fn from(configs: Vec<ECHConfig>) -> Self {
        Self { configs }
    }
}

impl ReadFromCursor for ECHConfigList {
    fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> io::Result<Self> {
        let mut configs = Vec::new();

        let configs_length = cursor.read_u16::<BigEndian>()?;
        log::trace!("ECHConfigList length = {}", configs_length);

        cursor.with_truncated(configs_length.into(), |cursor, _| {
            while cursor.std_remaining_slice().len() > 0 {
                let config = ECHConfig::read_from(cursor)?;
                configs.push(config);
            }
            Ok(Self { configs })
        })
    }
}

impl ReadFromCursor for ECHConfig {
    fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> io::Result<Self> {
        let version = cursor.read_u16::<BigEndian>()?;
        log::trace!("ECHConfig version = 0x{:04x}", version);
        let length = cursor.read_u16::<BigEndian>()?;
        log::trace!("ECHConfig length  = {}", length);
        let contents = match version {
            0xfe0d => cursor.with_truncated(
                u64::from(length),
                |cursor, _len_hint| -> io::Result<ECHConfigContents> {
                    let key_config = tls13::HpkeKeyConfig::read_from(cursor)?;
                    log::trace!("key_config = {:?}", key_config);
                    let maximum_name_length = cursor.read_u8()?;
                    log::trace!("maximum_name_length = {}", maximum_name_length);
                    let public_name = PublicName::read_from(cursor)?;

                    let mut extensions = Vec::new();

                    let extensions_len = cursor.read_u16::<BigEndian>()?;
                    log::trace!("extensions: len = {}", extensions_len);
                    cursor.with_truncated(
                        extensions_len as u64,
                        |cursor, _| -> io::Result<()> {
                            while cursor.std_remaining_slice().len() > 0 {
                                let ext = tls13::Extension::read_from(cursor)?;
                                extensions.push(ext);
                            }
                            Ok(())
                        },
                    )?;

                    Ok(ECHConfigContents::Version0xfe0d {
                        key_config,
                        maximum_name_length,
                        public_name,
                        extensions,
                    })
                },
            )?,
            _ => {
                let opq = Opaque::read_known_len(cursor, length)?;
                ECHConfigContents::UnknownECHVersion(opq)
            }
        };
        Ok(Self { version, contents })
    }
}

#[derive(Clone, PartialEq, Deserialize, Serialize)]
pub struct PublicName(pub Vec<u8>);

impl fmt::Debug for PublicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.0[..];
        String::from_utf8_lossy(bytes).fmt(f)
    }
}

impl fmt::Display for PublicName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.0[..];
        String::from_utf8_lossy(bytes).fmt(f)
    }
}

impl std::str::FromStr for PublicName {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if (1..=254).contains(&s.len()) {
            Ok(Self(s.as_bytes().to_vec()))
        } else {
            Err("string length not in range 1..=254")
        }
    }
}

impl ReadFromCursor for PublicName {
    fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> io::Result<Self> {
        let len = cursor.read_u8()?;
        log::trace!("PublicName length = {}", len);
        if len == 0 || len > 254 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "length of opaque field was zero, but must be at least 1",
            ));
        }
        let mut vec = vec![0u8; usize::from(len)];
        cursor.read_exact(&mut vec)?;
        log::trace!("PublicName = {:?}", std::str::from_utf8(&vec));
        Ok(Self(vec))
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct ECHConfig {
    pub version: u16,
    pub contents: ECHConfigContents,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ECHConfigContents {
    // if version == 0xfe0d
    Version0xfe0d {
        key_config: tls13::HpkeKeyConfig,
        maximum_name_length: u8,
        // min len 1, max len 255
        #[serde(with = "serde_with::rust::display_fromstr")]
        public_name: PublicName,

        // any length up to 65535
        //
        // each is a TLS 1.3 Extension, defined in RFC8446 section 4.2
        //
        // > extensions MAY appear in any order, but
        // > there MUST NOT be more than one extension of the same type in the
        // > extensions block.  An extension can be tagged as mandatory by using
        // > an extension type codepoint with the high order bit set to 1.

        // > Clients MUST parse the extension list and check for unsupported
        // > mandatory extensions.  If an unsupported mandatory extension is
        // > present, clients MUST ignore the "ECHConfig".
        extensions: Vec<tls13::Extension>,
    },
    UnknownECHVersion(Opaque<0, { u16::MAX }>),
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum EncryptedClientHello {
    Outer {
        cipher_suite: tls13::HpkeSymmetricCipherSuite,
        config_id: u8,
        enc: Opaque<0, { u16::MAX }>,
        payload: Opaque<1, { u16::MAX }>,
    },
    Inner,
}

u16_enum! {
    #[derive(Deserialize, Serialize)]
    pub enum ECHClientHelloType {
        Outer = 0,
        Inner = 1,
    }
}

impl ReadFromCursor for EncryptedClientHello {
    fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
        let ty: ECHClientHelloType = cursor.read_u16::<BigEndian>()?.try_into()?;
        Ok(match ty {
            ECHClientHelloType::Inner => EncryptedClientHello::Inner,
            ECHClientHelloType::Outer => EncryptedClientHello::Outer {
                cipher_suite: ReadFromCursor::read_from(cursor)?,
                config_id: cursor.read_u8()?,
                enc: Opaque::read_from(cursor)?,
                payload: Opaque::read_from(cursor)?,
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct EchOuterExtensions {
    outer: Vec<tls13::ExtensionType>,
}

pub mod tls13 {
    use crate::cursor_ext::{Ascii, CursorExt, Opaque, ReadFromCursor};
    use byteorder::{BigEndian, ReadBytesExt};
    use serde::{Deserialize, Serialize};
    use std::io;

    // mandatory-to-implement extensions from RFC8446
    //
    // -  Supported Versions ("supported_versions"; Section 4.2.1)
    // -  Cookie ("cookie"; Section 4.2.2)
    // -  Signature Algorithms ("signature_algorithms"; Section 4.2.3)
    // -  Signature Algorithms Certificate ("signature_algorithms_cert"; Section 4.2.3)
    // -  Negotiated Groups ("supported_groups"; Section 4.2.7)
    // -  Key Share ("key_share"; Section 4.2.8)
    // -  Server Name Indication ("server_name"; Section 3 of [RFC6066])
    //
    #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub enum Extension {
        /// `encrypted_client_hello`
        EncryptedClientHello(super::EncryptedClientHello),
        /// `ech_outer_extensions`
        EchOuterExtensions(super::EchOuterExtensions),

        /// `server_name`. This is the SNI field.
        ///
        /// This probably shouldn't appear in an ECH config! The whole point is to avoid it!
        /// So we'll parse it to show if it's being used
        ServerName(ServerName),

        /// `supported_versions` (TLS version negotiation)
        SupportedVersions(SupportedVersions),

        // /// `supported_groups`
        // SupportedGroups(NamedGroupList),

        // /// `cookie`
        // Cookie(Cookie),

        // /// `key_share`
        // ///
        // /// We assume a KeyShareClientHello version of this structure, because these
        // /// extensions are for adding to a client hello message
        // KeyShare(KeyShareClientHello),
        Other(ExtensionType, UnknownExtension),
    }

    impl ReadFromCursor for Extension {
        fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
            let ty: ExtensionType = cursor.read_u16::<BigEndian>()?.into();
            log::trace!("TLS extension: {:?}", ty);
            let remain = cursor.std_remaining_slice();
            log::trace!("TLS remaining: {:?}", remain);
            let len = cursor.read_u16::<BigEndian>()?;
            log::trace!("TLS extension length: {:?}", len);
            cursor.with_truncated(len as u64, |cursor, len_hint| {
                log::trace!("TLS extension length hint: {:?}", len_hint);
                match ty {
                    // ExtensionType::ServerName => Extension::ServerName(ServerName::read_)
                    _ => Ok(Extension::Other(
                        ty,
                        UnknownExtension::read_len(cursor, len)?,
                    )),
                }
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub struct UnknownExtension(Opaque<0, { u16::MAX }>);

    impl UnknownExtension {
        fn read_len(cursor: &mut io::Cursor<&[u8]>, len: u16) -> io::Result<Self> {
            let vec = crate::cursor_ext::read_vec_of_len(cursor, 0..=u16::MAX, len)?;
            Ok(Self(Opaque(vec)))
        }
    }

    #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub enum ServerName {
        // name type 0x0000
        HostName(HostName),
        Unknown(UnknownNameType),
    }
    pub type NameType = u16;

    pub type HostName = Ascii;
    pub type UnknownNameType = Opaque<0, { u16::MAX }>;

    u16_enum! {
        /// Draft RFC <https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.txt>
        /// 7.1.  Key Encapsulation Mechanisms (KEMs)
        #[allow(non_camel_case_types)]
        #[derive(Deserialize, Serialize)]
        pub enum HpkeKemId {
            Reserved = 0x0000,
            DHKEM_P256_HKDF_SHA256 = 0x0010,
            DHKEM_P384_HKDF_SHA384 = 0x0011,
            DHKEM_P512_HKDF_SHA512 = 0x0012,
            DHKEM_X25519_HKDF_SHA512 = 0x0020,
            DHKEM_X448_HKDF_SHA512 = 0x0021,
            @unknown Unknown(u16),
        }
    }

    u16_enum! {
        /// Draft RFC <https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.txt>
        /// 7.2.  Key Derivation Functions (KDFs)
        #[allow(non_camel_case_types)]
        #[derive(Deserialize, Serialize)]
        pub enum HpkeKdfId {
            Reserved = 0,
            HKDF_SHA256 = 1,
            HKDF_SHA384 = 2,
            HKDF_SHA512 = 3,
            @unknown Unknown(u16),
        }
    }

    u16_enum! {
        /// Draft RFC <https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.txt>
        /// 7.3.  Authenticated Encryption with Associated Data (AEAD) Functions
        #[allow(non_camel_case_types)]
        #[derive(Deserialize, Serialize)]
        pub enum HpkeAeadId {
            Reserved = 0,
            AES_128_GCM = 1,
            AES_256_GCM = 2,
            ChaCha20Poly1305 = 3,
            @unknown Unknown(u16),
            ExportOnly = 0xffff,
        }
    }

    #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub struct HpkeSymmetricCipherSuite {
        pub kdf_id: HpkeKdfId,
        pub aead_id: HpkeAeadId,
    }

    impl ReadFromCursor for HpkeSymmetricCipherSuite {
        fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
            Ok(Self {
                kdf_id: cursor.read_u16::<BigEndian>()?.into(),
                aead_id: cursor.read_u16::<BigEndian>()?.into(),
            })
        }
    }

    #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub struct HpkeKeyConfig {
        pub config_id: u8,
        pub kem_id: HpkeKemId,
        pub public_key: HpkePublicKey,
        // u16 len
        pub cipher_suites: Vec<HpkeSymmetricCipherSuite>,
    }

    impl ReadFromCursor for HpkeKeyConfig {
        fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
            let config_id = cursor.read_u8()?;
            log::trace!("config_id = {:?}", config_id);
            let kem_id = cursor.read_u16::<BigEndian>()?.into();
            log::trace!("kem_id = {:?}", kem_id);
            let public_key = HpkePublicKey::read_from(cursor)?;
            log::trace!("public_key (len) = {:?}", public_key.0.len());
            let cs_len = cursor.read_u16::<BigEndian>()?;
            log::trace!("cs_len = {:?}", cs_len);
            if cs_len < 4 || cs_len as u32 > 2u32 << 16 - 4 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cipher_suites length field invalid",
                ));
            }
            let n_cipher_suites = cs_len as usize / 4;
            log::trace!("n_cipher_suites = {:?}", n_cipher_suites);
            let mut cipher_suites = Vec::with_capacity(n_cipher_suites);
            for _ in 0..n_cipher_suites {
                let suite = HpkeSymmetricCipherSuite::read_from(cursor)?;
                cipher_suites.push(suite);
            }
            Ok(Self {
                config_id,
                kem_id,
                public_key,
                cipher_suites,
            })
        }
    }

    // opaque!(pub struct HpkePublicKey<1, {u16::MAX}>);
    pub type HpkePublicKey = Opaque<1, { u16::MAX }>;

    #[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
    pub struct SupportedVersions {
        // min length 2 (otherwise implied by TLS version field), max length 254
        // len is a u8 i suppose?
        pub versions: Vec<TlsVersion>,
    }

    u16_enum! {
        #[derive(Deserialize, Serialize)]
        pub enum TlsVersion {
            Ssl3_0 = 0x300,
            Tls1_0 = 0x301,
            Tls1_1 = 0x302,
            Tls1_2 = 0x303,
            Tls1_3 = 0x304,
            @unknown Other(u16),
        }
    }

    // opaque!(pub struct Cookie);

    u16_enum! {
        #[derive(Deserialize, Serialize)]
        pub enum ExtensionType {
            ServerName = 0,                           /* RFC 6066 */
            MaxFragmentLength = 1,                    /* RFC 6066 */
            StatusRequest = 5,                        /* RFC 6066 */
            SupportedGroups = 10,                     /* RFC 8422, 7919 */
            SignatureAlgorithms = 13,                 /* RFC 8446 */
            UseSrtp = 14,                             /* RFC 5764 */
            Heartbeat = 15,                           /* RFC 6520 */
            ApplicationLayerProtocolNegotiation = 16, /* RFC 7301 */
            SignedCertificateTimestamp = 18,          /* RFC 6962 */
            ClientCertificateType = 19,               /* RFC 7250 */
            ServerCertificateType = 20,               /* RFC 7250 */
            Padding = 21,                             /* RFC 7685 */
            PreSharedKey = 41,                        /* RFC 8446 */
            EarlyData = 42,                           /* RFC 8446 */
            SupportedVersions = 43,                   /* RFC 8446 */
            Cookie = 44,                              /* RFC 8446 */
            PskKeyExchangeModes = 45,                 /* RFC 8446 */
            CertificateAuthorities = 47,              /* RFC 8446 */
            OidFilters = 48,                          /* RFC 8446 */
            PostHandshakeAuth = 49,                   /* RFC 8446 */
            SignatureAlgorithmsCert = 50,             /* RFC 8446 */
            KeyShare = 51,                            /* RFC 8446 */
            // This is the ECH extension
            EncryptedClientHello = 0xfe0d,
            EchOuterExtensions = 0xfd00,
            @unknown Other(u16),
        }
    }
}

#[cfg(test)]
mod test {
    use super::tls13::*;
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn cloudflare() {
        init_logs();
        // from crypto.cloudflare.com
        let public_key: [u8; 32] = [
            40, 38, 25, 12, 212, 168, 183, 42, 218, 32, 41, 154, 44, 61, 152, 136, 131, 114, 86,
            111, 194, 66, 154, 114, 231, 170, 205, 83, 72, 105, 105, 119,
        ];
        let buf = &[
            0, 70, // echconfiglist: len = 70
            254, 13, // config version: 0xfe0d
            0, 66, // config len
            63, // config id
            0, 32, 0, 32, // hpke stuff
            40, 38, 25, 12, 212, 168, 183, 42, 218, 32, 41, 154, 44, 61, 152, 136, 131, 114, 86,
            111, 194, 66, 154, 114, 231, 170, 205, 83, 72, 105, 105, 119, // public_key
            0, 4, // cipher suites len
            0, 1, 0, 1, // cipher suites
            0, 19, // public name
            99, 108, 111, 117, 100, 102, 108, 97, 114, 101, 45, 101, 115, 110, 105, 46, 99, 111,
            109, // cloudflare-esni.com
            0, 0, // extensions len
        ];
        let expected = ECHConfigList {
            configs: vec![ECHConfig {
                version: 0xfe0d,
                contents: ECHConfigContents::Version0xfe0d {
                    key_config: HpkeKeyConfig {
                        config_id: 63,
                        kem_id: HpkeKemId::DHKEM_X25519_HKDF_SHA512,
                        cipher_suites: vec![HpkeSymmetricCipherSuite {
                            kdf_id: HpkeKdfId::HKDF_SHA256,
                            aead_id: HpkeAeadId::AES_128_GCM,
                        }],
                        public_key: public_key.to_vec().try_into().unwrap(),
                    },
                    maximum_name_length: 0,
                    public_name: PublicName(b"cloudflare-esni.com".to_vec()),
                    extensions: vec![],
                },
            }],
        };

        assert_eq!(
            ECHConfigList::read_from(&mut io::Cursor::new(buf))
                .map_err(|e| e.to_string())
                .as_ref(),
            Ok(&expected)
        );
        // this is what google returned for HTTPS crypto.cloudflare.com on 2021-09-26
        let base = "AEb+DQBCPwAgACAoJhkM1Ki3KtogKZosPZiIg3JWb8JCmnLnqs1TSGlpdwAEAAEAAQATY2xvdWRmbGFyZS1lc25pLmNvbQAA";
        assert_eq!(base64::encode(buf), base);

        assert_eq!(
            ECHConfigList::from_base64(base)
                .map_err(|e| e.to_string())
                .as_ref(),
            Ok(&expected),
        );
    }

}

#[cfg(test)]
fn init_logs() {
    use std::sync::Once;
    static LOG_INIT: Once = Once::new();
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}
