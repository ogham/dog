//! The format of both SVCB and HTTPS RRs is identical.

use core::fmt;
use std::collections::HashMap;
use std::io::{self, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr};

use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;

/// A kinda hacky but alright way to avoid copying tons of data
trait CursorExt {
    /// Replace this when #[feature(cursor_remaining)] is stabilised
    fn std_remaining_slice(&self) -> &[u8];

    /// Convenience
    fn truncated(&self, length: u64) -> Self;
    fn with_truncated<T>(&mut self, length: u64, f: impl FnOnce(&mut Self, usize) -> T) -> T;
}

impl CursorExt for Cursor<&[u8]> {
    fn std_remaining_slice(&self) -> &[u8] {
        let inner = self.get_ref();
        let len = self.position().min(inner.as_ref().len() as u64);
        &inner[(len as usize)..]
    }
    fn truncated(&self, to_length: u64) -> Self {
        let inner = self.get_ref();
        let len = inner.len() as u64;
        let start = self.position().min(len);
        let end = (start + to_length).min(len);
        let trunc = &inner[(start as usize)..(end as usize)];
        Cursor::new(trunc)
    }
    fn with_truncated<T>(&mut self, length: u64, f: impl FnOnce(&mut Self, usize) -> T) -> T {
        let mut trunc = self.truncated(length);
        let len_hint = trunc.get_ref().len();
        let ret = f(&mut trunc, len_hint);
        self.seek(SeekFrom::Current(trunc.position() as i64))
            .unwrap();
        ret
    }
}

macro_rules! u16_enum {
    {
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vattr:meta])*
                $variant:ident = $lit:literal,)+
        }
    } => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq)]
        #[repr(u16)]
        $vis enum $name {
            $(
                $(#[$vattr])*
                $variant = $lit,)+
        }
        impl core::convert::TryFrom<u16> for $name {
            type Error = std::io::Error;

            fn try_from(int: u16) -> Result<Self, Self::Error> {
                match int {
                    $($lit => Ok(Self::$variant),)+
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid value for {}: {:04x}", stringify!($name), int)
                        )
                    )
                }
            }
        }
    };
    {
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vattr:meta])*
                $variant:ident = $lit:literal,)+
            $(
                @unknown
                $(#[$uattr:meta])*
                $unknown:ident (u16),
                $(
                    $(#[$vattr2:meta])*
                    $variant2:ident = $lit2:literal,)*
            )?
        }
    } => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq)]
        #[repr(u16)]
        $vis enum $name {
            $(
                $(#[$vattr])*
                $variant = $lit,)+
            $(
                $(#[$uattr])*
                $unknown(u16),
                $(
                    $(#[$vattr2])*
                    $variant2 = $lit2,)*
            )?
        }
        impl From<u16> for $name {
            fn from(int: u16) -> Self {
                match int {
                    $($lit => Self::$variant,)+
                    $(
                        $($lit2 => Self::$variant2,)*
                        _ => Self::$unknown(int),
                    )?
                }
            }
        }
    };
}

// TODO: reimplement debug and use ... to truncate (base64?) output
#[derive(Debug, Clone, PartialEq)]
pub struct Opaque(/* u16 len */ Vec<u8>);

/// Same as [Opaque] but min length is 1
#[derive(Debug, Clone, PartialEq)]
pub struct Opaque1(/* u16 len */ Vec<u8>);

trait ReadFromCursor: Sized {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self>;
}

impl ReadFromCursor for Opaque {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let len = cursor.read_u16::<BigEndian>()?;
        log::trace!("read opaque length = {}", len);
        let mut vec = vec![0u8; usize::from(len)];
        cursor.read_exact(&mut vec[..])?;
        Ok(Opaque(vec))
    }
}

impl ReadFromCursor for Opaque1 {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let len = cursor.read_u16::<BigEndian>()?;
        log::trace!("read opaque1 length = {}", len);
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "length of opaque field was zero, but must be at least 1",
            ));
        }
        let mut vec = vec![0u8; usize::from(len)];
        cursor.read_exact(&mut vec[..])?;
        Ok(Opaque1(vec))
    }
}

macro_rules! opaque {
    ($vis:vis struct $ident:ident) => {
        #[derive(Debug, Clone, PartialEq)]
        $vis struct $ident($crate::record::svcb_https::Opaque);
        impl $crate::record::svcb_https::ReadFromCursor for $ident {
            fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
                $crate::record::svcb_https::Opaque::read_from(cursor).map(Self)
            }
        }
    }
}

/// A **SVCB** record, which contains an IP address as well as a port number,
/// for specifying the location of services more precisely.
///
/// # References
///
/// - [RFC Draft 7](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/07/) — A DNS RR for
///   specifying the location of services (February 2000)
#[derive(PartialEq, Debug)]
pub struct SVCB {
    priority: u16,
    target: Labels,
    parameters: Option<SvcParams>,
}

#[derive(PartialEq, Debug)]
pub struct HTTPS(SVCB);

u16_enum! {
    ///  14.3.2. Initial contents (subject to IANA additions)
    #[derive(Copy, Eq, PartialOrd, Hash)]
    enum SvcParam {
        /// `mandatory`
        Mandatory = 0,
        /// `alpn`
        Alpn = 1,
        /// `no-default-alpn`
        NoDefaultAlpn = 2,
        Port = 3,
        Ipv4Hint = 4,
        Ech = 5,
        Ipv6Hint = 6,
        @unknown KeyNNNNN(u16),
        InvalidKey = 65535,
    }
}

#[test]
fn svc_param_from_u16() {
    assert_eq!(SvcParam::from(12345u16), SvcParam::KeyNNNNN(12345u16));
}

impl fmt::Display for SvcParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Ok(match self {
            Self::Mandatory => f.write_str("mandatory")?,
            Self::Alpn => f.write_str("alpn")?,
            Self::NoDefaultAlpn => f.write_str("no-default-alpn")?,
            Self::Port => f.write_str("port")?,
            Self::Ipv4Hint => f.write_str("ipv4hint")?,
            Self::Ech => f.write_str("echconfig")?,
            Self::Ipv6Hint => f.write_str("ipv6hint")?,
            Self::KeyNNNNN(n) => write!(f, "key{}", n)?,
            Self::InvalidKey => f.write_str("[invalid key]")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
struct SvcParams {
    /// List of keys that must be understood by a client to use the RR properly.
    ///
    /// Wire format: list of u16 network endian svcparam values
    /// Presentation format: a comma-separated [ValueList]
    mandatory: Vec<SvcParam>,
    /// Draft 7 section 6.1
    ///
    /// Wire format:
    /// Presentation format: comma-separated list of alpn-id, 1-255 characters each
    /// (also, "Zone file implementations MAY disallow" commas/backslash escapes, use \002 (ascii
    /// 0x02 STX (start text) character). That's a TODO
    alpn: Option<Alpn>,
    port: Option<u16>,
    ipv4hint: Vec<Ipv4Addr>,
    /// An ECHConfigList from the [ECH RFC][ech-rfc]
    ///
    /// [ech-rfc]: https://datatracker.ietf.org/doc/draft-ietf-tls-esni/13/
    ///
    /// Wire format, the value of the parameter is an ECHConfigList [ECH], including the redundant length prefix.
    /// Presentation format, the value is a single ECHConfigList encoded in Base64 [base64].
    ech: Option<ech::ECHConfigList>,
    ipv6hint: Vec<Ipv6Addr>,

    /// For any unrecognised keys
    other: HashMap<SvcParam, Opaque>,
}

impl SvcParams {
    fn read(cursor: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let mut mandatory = Default::default();
        let mut no_default_alpn: Option<bool> = None;
        let mut alpn_ids = Default::default();
        let mut port = Default::default();
        let mut ipv4hint = Default::default();
        let mut ech = Default::default();
        let mut ipv6hint = Default::default();
        let mut other = HashMap::new();

        let mut last_param = None;

        while let Ok(param) = cursor.read_u16::<BigEndian>().map(SvcParam::from) {
            trace!("read param: {:?}", param);

            // clients must consider RR invalid if params not in "strictly increasing numeric order"
            // this implies no duplicate keys
            if let Some(last) = last_param.replace(param) {
                if param <= last {
                    error!("params out of order: read {:?} after {:?}", param, last,);
                    return Err(WireError::IO);
                }
            }

            let param_length = cursor.read_u16::<BigEndian>()?;
            trace!("read param length: {}", param_length);

            cursor.with_truncated(param_length as u64, |cursor, len_hint| {
                match param {
                    SvcParam::Mandatory => {
                        let mps = read_convert(cursor, len_hint, |c| c.read_u16::<BigEndian>())?;
                        // mandatory must not appear in its own value list
                        if mps.contains(&SvcParam::Mandatory) {
                            return Err(WireError::IO);
                        }
                        mandatory = mps
                    }

                    SvcParam::Ipv4Hint => {
                        ipv4hint = read_convert(cursor, len_hint, |c| c.read_u32::<BigEndian>())?;
                    }
                    SvcParam::Ech => {
                        let parsed = ech::ECHConfigList::read_from(cursor)?;
                        ech = Some(parsed);
                    }
                    SvcParam::Ipv6Hint => {
                        ipv6hint = read_convert(cursor, len_hint, |c| c.read_u128::<BigEndian>())?;
                    }
                    SvcParam::InvalidKey => {
                        return Err(WireError::IO);
                    }
                    SvcParam::NoDefaultAlpn => {
                        no_default_alpn = Some(false);
                    }
                    SvcParam::Alpn => {
                        let mut ids = Vec::new();
                        while let Ok(alpn_id) = AlpnId::read_from(cursor) {
                            trace!("read alpn_id {:?}", alpn_id);
                            ids.push(alpn_id)
                        }
                        if ids.is_empty() {
                            return Err(WireError::IO);
                        }
                        alpn_ids = ids;
                    }
                    SvcParam::KeyNNNNN(_) => {
                        let value = Opaque::read_from(cursor)?;
                        other.insert(param, value);
                    }
                    SvcParam::Port => {
                        port = Some(cursor.read_u16::<BigEndian>()?);
                    }
                }
                Ok(())
            })?;
        }

        if no_default_alpn.is_some() && alpn_ids.is_empty() {
            return Err(WireError::IO);
        }
        let alpn = if alpn_ids.is_empty() {
            None
        } else {
            Some(Alpn {
                alpn_ids,
                no_default_alpn: no_default_alpn.unwrap_or(false),
            })
        };

        Ok(Self {
            mandatory,
            alpn,
            port,
            ipv4hint,
            ech,
            ipv6hint,
            other,
        })
    }
}

fn read_convert<Raw: Sized, Nice: From<Raw>>(
    cursor: &mut Cursor<&[u8]>,
    len: usize,
    mut f: impl FnMut(&mut Cursor<&[u8]>) -> io::Result<Raw>,
) -> Result<Vec<Nice>, WireError> {
    let size = core::mem::size_of::<Raw>();
    if len % size != 0 {
        return Err(WireError::IO);
    }
    let mut collector = Vec::with_capacity(len / size);
    let reader = core::iter::from_fn(|| f(cursor).ok().map(Nice::from));
    collector.extend(reader);
    Ok(collector)
}

#[derive(Debug, Clone, PartialEq)]
struct Alpn {
    alpn_ids: Vec<AlpnId>,
    no_default_alpn: bool,
}

#[derive(Clone, PartialEq)]
#[repr(transparent)]
struct AlpnId(Vec<u8>);

impl From<&str> for AlpnId {
    fn from(s: &str) -> Self {
        let v = s.as_bytes().to_owned();
        AlpnId(v)
    }
}

impl ReadFromCursor for AlpnId {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let len = cursor.read_u8()?;
        trace!("alpn len {}", len);
        let mut vec = vec![0u8; len as _];
        cursor.read_exact(&mut vec)?;
        Ok(AlpnId(vec))
    }
}

impl fmt::Debug for AlpnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.0[..];
        f.write_str(&String::from_utf8_lossy(bytes))
    }
}

/// ECH RFC draft 13 section 4
mod ech {
    use core::fmt;
    use std::{
        convert::TryInto,
        io::{self, Read},
    };

    use byteorder::{BigEndian, ReadBytesExt};

    use super::{CursorExt, Opaque, Opaque1, ReadFromCursor};

    #[derive(Debug, Clone, PartialEq)]
    pub struct ECHConfigList {
        configs: Vec<ECHConfig>,

        /// Need a copy of the whole thing to encode as base64
        base64: String,
    }

    impl ReadFromCursor for ECHConfigList {
        fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> io::Result<Self> {
            let mut configs = Vec::new();
            let configs_length = cursor.read_u16::<BigEndian>()?;

            let buf = &cursor.std_remaining_slice()[..configs_length.into()];
            let base64 = base64::encode(buf);

            for _ in 0..configs_length {
                let config = ECHConfig::read_from(cursor)?;
                configs.push(config);
            }
            Ok(Self { configs, base64 })
        }
    }

    impl ReadFromCursor for ECHConfig {
        fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> io::Result<Self> {
            let version = cursor.read_u16::<BigEndian>()?;
            let length = cursor.read_u16::<BigEndian>()?;
            match version {
                0xfe0d => cursor.with_truncated(u64::from(length), |cursor, _len_hint| {
                    let key_config = tls13::HpkeKeyConfig::read_from(cursor)?;
                    let maximum_name_length = cursor.read_u8()?;
                    let public_name = PublicName::read_from(cursor)?;

                    let mut extensions = Vec::new();

                    while let ext = tls13::Extension::read_from(cursor)? {
                        extensions.push(ext);
                    }

                    Ok(Self::EchConfigContents {
                        key_config,
                        maximum_name_length,
                        public_name,
                        extensions,
                    })
                }),
                _ => {
                    let mut vec = vec![0u8; usize::from(length)];
                    cursor.read_exact(&mut vec)?;
                    Ok(ECHConfig::UnknownECHVersion(version, Opaque(vec)))
                }
            }
        }
    }

    #[derive(Clone, PartialEq)]
    pub struct PublicName {
        inner: Vec<u8>,
    }

    impl fmt::Debug for PublicName {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let bytes = &self.inner[..];
            f.write_str(&String::from_utf8_lossy(bytes))
        }
    }

    impl ReadFromCursor for PublicName {
        fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> io::Result<Self> {
            let len = cursor.read_u8()?;
            log::trace!("read ECHConfig.public_name length = {}", len);
            if len == 0 || len > 254 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "length of opaque field was zero, but must be at least 1",
                ));
            }
            let mut vec = vec![0u8; usize::from(len)];
            cursor.read_exact(&mut vec[..])?;
            Ok(Self { inner: vec })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum ECHConfig {
        // if version == 0xfe0d
        EchConfigContents {
            key_config: tls13::HpkeKeyConfig,
            maximum_name_length: u8,
            // min len 1, max len 255
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
        UnknownECHVersion(u16, Opaque),
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum EncryptedClientHello {
        Outer {
            cipher_suite: tls13::HpkeSymmetricCipherSuite,
            config_id: u8,
            enc: Opaque,
            payload: Opaque1,
        },
        Inner,
    }

    u16_enum! {
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
                    enc: super::Opaque::read_from(cursor)?,
                    payload: super::Opaque1::read_from(cursor)?,
                },
            })
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    pub struct EchOuterExtensions {
        outer: Vec<tls13::ExtensionType>,
    }

    mod tls13 {
        use byteorder::{BigEndian, ReadBytesExt};

        use crate::record::svcb_https::ReadFromCursor;

        // const MANDATORY: u16 = 0x1 << 15;

        // We will implement the mandatory-to-implement extensions only from RFC8446
        //
        // -  Supported Versions ("supported_versions"; Section 4.2.1)
        // -  Cookie ("cookie"; Section 4.2.2)
        // -  Signature Algorithms ("signature_algorithms"; Section 4.2.3)
        // -  Signature Algorithms Certificate ("signature_algorithms_cert"; Section 4.2.3)
        // -  Negotiated Groups ("supported_groups"; Section 4.2.7)
        // -  Key Share ("key_share"; Section 4.2.8)
        // -  Server Name Indication ("server_name"; Section 3 of [RFC6066])
        //
        #[derive(Debug, Clone, PartialEq)]
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
                match ty {
                    // ExtensionType::ServerName => Extension::ServerName(ServerName::read_)
                    _ => Ok(Extension::Other(ty, UnknownExtension::read_from(cursor)?)),
                }
            }
        }

        opaque!(pub struct UnknownExtension);

        #[derive(Debug, Clone, PartialEq)]
        pub enum ServerName {
            // name type 0x0000
            HostName(HostName),
            Unknown(UnknownNameType),
        }
        pub type NameType = u16;

        opaque!(pub struct HostName);
        opaque!(pub struct UnknownNameType);

        u16_enum! {
            /// Draft RFC <https://www.ietf.org/archive/id/draft-irtf-cfrg-hpke-11.txt>
            /// 7.1.  Key Encapsulation Mechanisms (KEMs)
            #[allow(non_camel_case_types)]
            enum HpkeKemId {
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
            enum HpkeKdfId {
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
            enum HpkeAeadId {
                Reserved = 0,
                AES_128_GCM = 1,
                AES_256_GCM = 2,
                ChaCha20Poly1305 = 3,
                @unknown Unknown(u16),
                ExportOnly = 0xffff,
            }
        }

        #[test]
        fn test_hpke() {
            let hpke = HpkeAeadId::from(0x0003);
        }

        #[derive(Debug, Clone, PartialEq)]
        pub struct HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdfId,
            aead_id: HpkeAeadId,
        }

        impl ReadFromCursor for HpkeSymmetricCipherSuite {
            fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
                Ok(Self {
                    kdf_id: cursor.read_u16::<BigEndian>()?.into(),
                    aead_id: cursor.read_u16::<BigEndian>()?.into(),
                })
            }
        }

        #[derive(Debug, Clone, PartialEq)]
        pub struct HpkeKeyConfig {
            config_id: u8,
            kem_id: HpkeKemId,
            public_key: HpkePublicKey,
            // u16 len
            cipher_suites: Vec<HpkeSymmetricCipherSuite>,
        }

        impl ReadFromCursor for HpkeKeyConfig {
            fn read_from(cursor: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
                let config_id = cursor.read_u8()?;
                let kem_id = cursor.read_u16::<BigEndian>()?.into();
                let public_key = HpkePublicKey::read_from(cursor)?;
                let cs_len = cursor.read_u16::<BigEndian>()?;
                let n_cipher_suites =
                    cs_len as usize / core::mem::size_of::<HpkeSymmetricCipherSuite>();
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

        opaque!(pub struct HpkePublicKey);

        #[derive(Debug, Clone, PartialEq)]
        pub struct SupportedVersions {
            // min length 2 (otherwise implied by TLS version field), max length 254
            // len is a u8 i suppose?
            versions: Vec<TlsVersion>,
        }

        // #[derive(Debug, Clone, PartialEq)]
        // pub struct NamedGroupList(/* u16 len */ Vec<NamedGroup>);

        // u16_enum! {
        //     pub enum NamedGroup {
        //         /* Elliptic Curve Groups (ECDHE) */
        //         Secp256r1 = 0x0017,
        //         Secp384r1 = 0x0018,
        //         Secp521r1 = 0x0019,
        //         X25519 = 0x001D,
        //         X448 = 0x001E,
        //         /* Finite Field Groups (DHE) */
        //         Ffdhe2048 = 0x0100,
        //         Ffdhe3072 = 0x0101,
        //         Ffdhe4096 = 0x0102,
        //         Ffdhe6144 = 0x0103,
        //         Ffdhe8192 = 0x0104,
        //         /* Reserved Code Points */
        //         @unknown
        //         /// ffdhe_private_use(0x01FC..0x01FF),
        //         /// ecdhe_private_use(0xFE00..0xFEFF),
        //         PrivateUse(u16),
        //     }
        // }

        // #[derive(Debug, Clone, PartialEq)]
        // struct KeyShareEntry {
        //     group: NamedGroup,
        //     key_exchange: Vec<u8>,
        // }

        // #[derive(Debug, Clone, PartialEq)]
        // struct KeyShareClientHello {
        //     // u16 len
        //     client_shares: Vec<KeyShareEntry>,
        // }

        u16_enum! {
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
}

impl SvcParams {
    /// Takes a valid SvcParams struct and encodes it as human-readable input syntax
    /// The input syntax (not RDATA)
    //
    // ```text,ignore
    // alpha-lc      = %x61-7A   ;  a-z
    // SvcParamKey   = 1*63(alpha-lc / DIGIT / "-")
    // SvcParam      = SvcParamKey ["=" SvcParamValue]
    // SvcParamValue = char-string
    // value         = *OCTET
    // ```
    pub fn encode(&self) -> String {
        todo!()
    }
}

impl Wire for HTTPS {
    const NAME: &'static str = "HTTPS";
    const RR_TYPE: u16 = 65;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        // TODO: default mandatory fields? something like that?
        SVCB::read(stated_length, c).map(HTTPS)
    }
}

//
impl Wire for SVCB {
    const NAME: &'static str = "SVCB";
    const RR_TYPE: u16 = 64;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, cursor: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let initial_pos = cursor.position();

        let ret = cursor.with_truncated(
            stated_length as _,
            move |cursor, _| -> Result<Self, WireError> {
                let priority = cursor.read_u16::<BigEndian>()?;
                trace!("Parsed priority -> {:?}", priority);

                // technically the labels are uncompressed, but this will succeed, hope nobody is
                // out there compressing their labels in SVCB records
                let (target, _target_length) = cursor.read_labels()?;
                trace!("Parsed target -> {:?}", target);

                // AliasMode
                let alias_mode = priority == 0;

                let parameters = if alias_mode {
                    None
                } else {
                    Some(SvcParams::read(cursor)?)
                };
                let ret = Self {
                    priority,
                    target,
                    parameters,
                };
                Ok(ret)
            },
        )?;

        let total_read = (cursor.position() - initial_pos) as u16;
        if total_read != stated_length {
            warn!(
                "Length is incorrect (stated length {:?}, fields plus target length {:?})",
                stated_length, total_read
            );
            let remain = cursor.std_remaining_slice();
            warn!("remaining: {:?}", remain);
            Err(WireError::WrongLabelLength {
                stated_length,
                length_after_labels: total_read,
            })
        } else {
            Ok(ret)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    use std::sync::Once;

    fn init_logs() {
        static LOG_INIT: Once = Once::new();
        LOG_INIT.call_once(|| {
            env_logger::init();
        });
    }

    #[test]
    fn parses() {
        init_logs();
        // dog HTTPS cloudflare.com, I think
        let buf = &[
            0, 1, // priority 1
            0, // zero length target name
            // param
            0, 1, // alpn
            0, 24, // len 24
            2, 104, 51, // len 2 "h3"
            5, 104, 51, 45, 50, 57, // len 5 "h3-..."
            5, 104, 51, 45, 50, 56, // len 5 "h3-..."
            5, 104, 51, 45, 50, 55, // len 5 "h3-..."
            2, 104, 50, // len 2 "h2"
            // param
            0, 4, // ipv4hint
            0, 8, // len 8 (2 ipv4 addresses)
            104, 16, 132, 229, // address 1
            104, 16, 133, 229, // address 2
            // param
            0, 6, // ipv6hint
            0, 32, // len 32 (2 ipv6 addresses)
            38, 6, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 16, 132, 229, // 2606:4700::6810:84e5
            38, 6, 71, 0, 0, 0, 0, 0, 0, 0, 0, 0, 104, 16, 133, 229, // 2606:4700::6810:85e8
        ];

        let result = HTTPS::read(buf.len() as _, &mut Cursor::new(buf)).unwrap();
        assert_eq!(
            result,
            HTTPS(SVCB {
                priority: 1,
                target: Labels::root(),
                parameters: Some(SvcParams {
                    mandatory: vec![],
                    alpn: Some(Alpn {
                        alpn_ids: vec![
                            "h3".into(),
                            "h3-29".into(),
                            "h3-28".into(),
                            "h3-27".into(),
                            "h2".into()
                        ],
                        no_default_alpn: false
                    }),
                    port: None,
                    ipv4hint: vec![
                        "104.16.132.229".parse().unwrap(),
                        "104.16.133.229".parse().unwrap()
                    ],
                    ech: None,
                    ipv6hint: vec![
                        "2606:4700::6810:84e5".parse().unwrap(),
                        "2606:4700::6810:85e5".parse().unwrap()
                    ],
                    other: HashMap::new(),
                }),
            })
        );
    }

    #[test]
    fn corrupted_alpn() {
        init_logs();
        let buf = &[
            0x00, 0x01, // SvcPriority
            0,    // TargetName = .
            // SvcParams
            0, 1, 0, 0, 0, 0, 0, // corrupted alpn record, len 0 despite covering three bytes
            0, 3, 0, 2, 0x01, 0xbb, // port, len 2, "443"
        ];
        assert_eq!(SVCB::read(16, &mut Cursor::new(buf)), Err(WireError::IO));
    }

    #[test]
    fn incorrect_record_length() {
        init_logs();
        let buf = &[
            0, 1, // SvcPriority
            0, // TargetName = .
            // SvcParams
            0, 3, 0, 2, 0x01, 0xbb, // port, len 2, "443"
        ];
        assert_eq!(
            SVCB::read(16, &mut Cursor::new(buf)),
            Err(WireError::WrongLabelLength {
                stated_length: 16,
                length_after_labels: 9
            })
        );
    }

    #[test]
    fn record_empty() {
        init_logs();
        assert_eq!(SVCB::read(0, &mut Cursor::new(&[])), Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        init_logs();
        let buf = &[
            0x00, // half a priority
        ];

        assert_eq!(SVCB::read(23, &mut Cursor::new(buf)), Err(WireError::IO));
    }
}
