//! The format of both SVCB and HTTPS RRs is identical.

use core::fmt;
use std::collections::BTreeMap;
use std::io::{self, Seek, SeekFrom};
use std::net::{Ipv4Addr, Ipv6Addr};

use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;

use crate::value_list::encoding;

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
/// An opaque piece of data, e.g. [SvcParams::ech]
#[derive(Debug, Clone, PartialEq)]
pub struct Opaque(Vec<u8>);

impl From<Vec<u8>> for Opaque {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl fmt::Display for Opaque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        encoding::EscapeCharString(&self.0).fmt(f)
    }
}

/// Same as [Opaque] but min length is 1
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Opaque1(Vec<u8>);

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

/// A **SVCB** (*service binding*) record, which holds information needed to make connections to
/// network services, such as for HTTPS origins.
///
/// # References
///
/// - [RFC Draft 7](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/07/) — A DNS RR for
///   specifying the location of services (February 2000)
#[derive(PartialEq, Debug)]
pub struct SVCB {
    /// The priority of this record (relative to others, with lower values preferred). A value of 0
    /// indicates AliasMode.
    pub priority: u16,
    /// The domain name of either the alias target (for AliasMode) or the alternative endpoint (for
    /// ServiceMode).
    pub target: Labels,
    /// The SvcParams
    pub params: Option<SvcParams>,
}

/// An **HTTPS** record, which is the HTTPS incarnation of **SVCB**.
#[derive(PartialEq, Debug)]
pub struct HTTPS {
    /// The underlying SVCB record
    pub svcb: SVCB,
}

impl HTTPS {
    /// Constructor
    pub fn new(svcb: SVCB) -> Self {
        Self { svcb }
    }
}

u16_enum! {
    ///  14.3.2. Initial contents (subject to IANA additions)
    #[derive(Copy, Eq, PartialOrd, Ord, Hash)]
    pub enum SvcParam {
        /// `mandatory`
        Mandatory = 0,
        /// `alpn`
        Alpn = 1,
        /// `no-default-alpn`
        NoDefaultAlpn = 2,
        /// `port`
        Port = 3,
        /// `ipv4hint`
        Ipv4Hint = 4,
        /// `ech`
        Ech = 5,
        /// `ipv6hint`
        Ipv6Hint = 6,
        @unknown
        /// `keyNNNNN`
        KeyNNNNN(u16),
        /// Invalid.
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
            Self::Ech => f.write_str("ech")?,
            Self::Ipv6Hint => f.write_str("ipv6hint")?,
            Self::KeyNNNNN(n) => write!(f, "key{}", n)?,
            Self::InvalidKey => f.write_str("[invalid key]")?,
        })
    }
}

/// The SvcParams section of a [SVCB] record
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SvcParams {
    /// List of keys that must be understood by a client to use the RR properly.
    ///
    /// Wire format: list of u16 network endian svcparam values
    /// Presentation format: a comma-separated [crate::value_list::ValueList]
    pub mandatory: Vec<SvcParam>,
    /// Draft 7 section 6.1
    ///
    /// Wire format:
    /// Presentation format: comma-separated list of alpn-id, 1-255 characters each
    /// (also, "Zone file implementations MAY disallow" commas/backslash escapes, use \002 (ascii
    /// 0x02 STX (start text) character). That's a TODO
    pub alpn: Option<Alpn>,
    /// > The "port" SvcParamKey defines the TCP or UDP port that should be used to reach this
    /// alternative endpoint. If this key is not present, clients SHALL use the authority
    /// endpoint's port number.
    pub port: Option<u16>,
    /// > The "ipv4hint" and "ipv6hint" keys convey IP addresses that clients MAY use to reach the
    /// service. If A and AAAA records for TargetName are locally available, the client SHOULD
    /// ignore these hints.
    pub ipv4hint: Vec<Ipv4Addr>,
    /// An ECHConfigList from the [ECH RFC][ech-rfc]
    ///
    /// [ech-rfc]: https://datatracker.ietf.org/doc/draft-ietf-tls-esni/13/
    ///
    /// Wire format: the value of the parameter is an ECHConfigList, including the redundant length prefix.
    /// Presentation format: the value is a single ECHConfigList encoded in Base64.
    pub ech: Option<Vec<u8>>,
    /// > The "ipv4hint" and "ipv6hint" keys convey IP addresses that clients MAY use to reach the
    /// service. If A and AAAA records for TargetName are locally available, the client SHOULD
    /// ignore these hints.
    pub ipv6hint: Vec<Ipv6Addr>,

    /// For any unrecognised keys. BTreeMap, because keys are sorted this way
    pub other: BTreeMap<SvcParam, Opaque>,
}

impl fmt::Display for SvcParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            mandatory,
            alpn,
            port,
            ipv4hint,
            ech,
            ipv6hint,
            other,
        } = self;
        if !mandatory.is_empty() {
            write!(
                f,
                " mandatory={}",
                display_utils::join(mandatory.iter(), ",")
            )?;
        }
        if let Some(alpn) = alpn {
            f.write_str(" alpn=")?;
            encoding::EscapeValueList(alpn.ids.iter().map(|id| id.0.as_slice())).fmt(f)?;
            if alpn.no_default_alpn {
                write!(f, " no-default-alpn")?;
            }
        }
        if let &Some(port) = port {
            write!(f, " port={}", port)?;
        }
        if !ipv4hint.is_empty() {
            write!(f, " ipv4hint={}", display_utils::join(ipv4hint.iter(), ","))?;
        }
        if let Some(ech) = ech {
            write!(
                f,
                " ech={}",
                base64::display::Base64Display::with_config(ech, base64::STANDARD)
            )?;
        }
        if !ipv6hint.is_empty() {
            write!(f, " ipv6hint={}", display_utils::join(ipv6hint.iter(), ","))?;
        }
        if !other.is_empty() {
            other
                .iter()
                .try_for_each(|(k, v)| write!(f, " {}={}", k, v))?;
        }
        Ok(())
    }
}

impl SvcParams {
    fn read(cursor: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let mut mandatory = Default::default();
        let mut no_default_alpn = false;
        let mut alpn_ids = Default::default();
        let mut port = Default::default();
        let mut ipv4hint = Default::default();
        let mut ech = Default::default();
        let mut ipv6hint = Default::default();
        let mut other = BTreeMap::new();

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
                        let mut vec = vec![0u8; len_hint];
                        cursor.read_exact(&mut vec)?;
                        ech = Some(vec);
                    }
                    SvcParam::Ipv6Hint => {
                        ipv6hint = read_convert(cursor, len_hint, |c| c.read_u128::<BigEndian>())?;
                    }
                    SvcParam::InvalidKey => {
                        return Err(WireError::IO);
                    }
                    SvcParam::NoDefaultAlpn => {
                        no_default_alpn = true;
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
                        let mut vec = vec![0u8; param_length as usize];
                        cursor.read_exact(&mut vec)?;
                        other.insert(param, Opaque(vec));
                    }
                    SvcParam::Port => {
                        port = Some(cursor.read_u16::<BigEndian>()?);
                    }
                }
                Ok(())
            })?;
        }

        if no_default_alpn && alpn_ids.is_empty() {
            return Err(WireError::IO);
        }
        let alpn = if alpn_ids.is_empty() {
            None
        } else {
            Some(Alpn {
                ids: alpn_ids,
                no_default_alpn,
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

/// The ALPN configuration, covering the `alpn` and `no-default-alpn` parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct Alpn {
    /// The `alpn` field
    pub ids: Vec<AlpnId>,
    /// The `no-default-alpn` field
    ///
    /// > To determine the set of protocol suites supported by an endpoint (the "SVCB ALPN set"), the client adds the default set to the list of alpn-ids unless the "no-default-alpn" SvcParamKey is present.
    pub no_default_alpn: bool,
}

/// An ALPN id, like "h2" or "h3-19"
#[derive(Clone, PartialEq)]
pub struct AlpnId(Vec<u8>);

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

impl fmt::Display for AlpnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.0[..];
        String::from_utf8_lossy(bytes).fmt(f)
    }
}

impl fmt::Debug for AlpnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = &self.0[..];
        String::from_utf8_lossy(bytes).fmt(f)
    }
}

impl Wire for HTTPS {
    const NAME: &'static str = "HTTPS";
    const RR_TYPE: u16 = 65;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        // TODO: default mandatory fields? something like that?
        SVCB::read(stated_length, c).map(HTTPS::new)
    }
}

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

                // ServiceMode
                let service_mode = priority > 0;

                // parse them anyway, but reduce to None if in alias mode
                let parameters = Some(SvcParams::read(cursor)?).filter(|_| service_mode);
                let ret = Self {
                    priority,
                    target,
                    params: parameters,
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
            Err(WireError::WrongLabelLength {
                stated_length,
                length_after_labels: total_read,
            })
        } else {
            Ok(ret)
        }
    }
}

impl fmt::Display for HTTPS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.svcb.fmt(f)
    }
}

impl fmt::Display for SVCB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            priority,
            target,
            params: parameters,
        } = self;

        write!(f, "{} {}", priority, target)?;
        if let Some(params) = parameters {
            write!(f, "{}", params)?;
        }
        Ok(())
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

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

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
            HTTPS::new(SVCB {
                priority: 1,
                target: Labels::root(),
                params: Some(SvcParams {
                    mandatory: vec![],
                    alpn: Some(Alpn {
                        ids: vec![
                            "h3".into(),
                            "h3-29".into(),
                            "h3-28".into(),
                            "h3-27".into(),
                            "h2".into()
                        ],
                        no_default_alpn: false,
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
                    other: BTreeMap::new(),
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
    fn ignore_alias_mode_params() {
        init_logs();
        let buf = &[
            0, 0, // SvcPriority 0, therefore AliasMode
            0, // TargetName = .
            // SvcParams
            0, 3, 0, 2, 0x01, 0xbb, // port, len 2, "443"
        ];
        assert_eq!(
            SVCB::read(9, &mut Cursor::new(buf)),
            Ok(SVCB {
                priority: 0,
                target: Labels::root(),
                params: None,
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

/// See the draft RFC
#[cfg(test)]
mod test_vectors {
    use crate::value_list::ValueList;

    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn alias_form() {
        init_logs();
        let buf = b"\x00\x00\x03foo\x07example\x03com\x00";
        let value = SVCB {
            priority: 0,
            target: Labels::encode("foo.example.com").unwrap(),
            params: None,
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );
        assert_eq!(value.to_string(), "0 foo.example.com.");
    }

    #[test]
    fn service_form() {
        init_logs();
        let buf = b"\x00\x01\x00";
        let value = SVCB {
            priority: 1,
            target: Labels::encode(".").unwrap(),
            params: Some(SvcParams::default()),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );
        assert_eq!(value.to_string(), "1 .");
    }

    #[test]
    fn service_form_2() {
        init_logs();
        let buf = &[
            0x00, 0x10, // priority
            0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, // target
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00,
            0x03, // key 3
            0x00, 0x02, // length 2
            0x00, 0x35, // value
        ];
        let value = SVCB {
            priority: 16,
            target: Labels::encode("foo.example.com.").unwrap(),
            params: Some(SvcParams {
                port: Some(53),
                ..SvcParams::default()
            }),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );
        assert_eq!(value.to_string(), "16 foo.example.com. port=53");
    }

    #[test]
    fn service_form_3() {
        init_logs();
        let buf = &[
            0x00, 0x01, // priority
            0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, // target
            0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, //
            0x03, 0x63, 0x6f, 0x6d, 0x00, //
            0x02, 0x9b, // key 667
            0x00, 0x05, // length 5
            0x68, 0x65, 0x6c, 0x6c, 0x6f, // value
        ];
        let value = SVCB {
            priority: 1,
            target: Labels::encode("foo.example.com.").unwrap(),
            params: Some(SvcParams {
                other: {
                    let mut map = BTreeMap::new();
                    map.insert(
                        SvcParam::KeyNNNNN(667),
                        Opaque(vec![0x68, 0x65, 0x6c, 0x6c, 0x6f]),
                    );
                    map
                },
                ..SvcParams::default()
            }),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );
        assert_eq!(value.to_string(), "1 foo.example.com. key667=hello");
    }

    #[test]
    fn service_form_4() {
        let buf = &[
            0x00, 0x01, // priority
            0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, // target
            0x02, 0x9b, // key 667
            0x00, 0x09, // length 9
            0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xd2, /* \210 */
            0x71, 0x6f, 0x6f, // value
        ];
        let value = SVCB {
            priority: 1,
            target: Labels::encode("foo.example.com.").unwrap(),
            params: Some(SvcParams {
                other: {
                    let mut map = BTreeMap::new();
                    map.insert(
                        SvcParam::KeyNNNNN(667),
                        Opaque(vec![0x68, 0x65, 0x6c, 0x6c, 0x6f, 0xd2, 0x71, 0x6f, 0x6f]),
                    );
                    map
                },
                ..SvcParams::default()
            }),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );

        // we avoid writing the quotes on values where possible, so this differs from the test
        // vector (which is for a parser, not a formatter?)
        assert_eq!(
            value.to_string(),
            r#"1 foo.example.com. key667=hello\210qoo"#
        );
    }

    #[test]
    fn service_form_5() {
        let buf = &[
            0x00, 0x01, // priority
            0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, // target
            0x00, 0x06, // key 6
            0x00, 0x20, // length 0x32,
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, // first address
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,
            0x00, 0x01, // second address
        ];
        let value = SVCB {
            priority: 1,
            target: Labels::encode("foo.example.com.").unwrap(),
            params: Some(SvcParams {
                ipv6hint: vec![
                    "2001:db8::1".parse().unwrap(),
                    "2001:db8::53:1".parse().unwrap(),
                ],
                ..Default::default()
            }),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );

        // we avoid writing the quotes on values where possible, so this differs from the test
        // vector (which is for a parser, not a formatter?)
        assert_eq!(
            value.to_string(),
            "1 foo.example.com. ipv6hint=2001:db8::1,2001:db8::53:1"
        );
    }

    #[test]
    fn service_form_6() {
        let buf = &[
            0x00, 0x01, // priority
            0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, // target
            0x00, 0x06, // key 6
            0x00, 0x10, // length 0x32,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc6, 0x33,
            0x64, 0x64, // first address
        ];
        let value = SVCB {
            priority: 1,
            target: Labels::encode("foo.example.com.").unwrap(),
            params: Some(SvcParams {
                ipv6hint: vec!["::ffff:198.51.100.100".parse().unwrap()],
                ..Default::default()
            }),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );

        // we avoid writing the quotes on values where possible, so this differs from the test
        // vector (which is for a parser, not a formatter?)
        assert_eq!(
            value.to_string(),
            "1 foo.example.com. ipv6hint=::ffff:198.51.100.100"
        );
    }

    #[test]
    fn service_form_7() {
        let buf = &[
            0x00, 0x10, // priority
            0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f,
            0x72, 0x67, 0x00, // target
            0x00, 0x00, // key 0
            0x00, 0x04, // param length 4
            0x00, 0x01, // value: key 1
            0x00, 0x04, // value: key 4
            0x00, 0x01, // key 1
            0x00, 0x09, // param length 9
            0x02, // alpn length 2
            0x68, 0x32, // alpn value
            0x05, // alpn length 5
            0x68, 0x33, 0x2d, 0x31, 0x39, // alpn value
            0x00, 0x04, // key 4
            0x00, 0x04, // param length 4
            0xc0, 0x00, 0x02, 0x01, // param value
        ];
        let value = SVCB {
            priority: 16,
            target: Labels::encode("foo.example.org.").unwrap(),
            params: Some(SvcParams {
                mandatory: vec![SvcParam::Alpn, SvcParam::Ipv4Hint],
                alpn: Some(Alpn {
                    ids: vec!["h2".into(), "h3-19".into()],
                    no_default_alpn: false,
                }),
                ipv4hint: vec!["192.0.2.1".parse().unwrap()],
                ..Default::default()
            }),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );

        assert_eq!(
            value.to_string(),
            "16 foo.example.org. mandatory=alpn,ipv4hint alpn=h2,h3-19 ipv4hint=192.0.2.1"
        );
    }

    #[test]
    fn service_form_8() {
        let buf = &[
            0x00, 0x10, // priority
            0x03, 0x66, 0x6f, 0x6f, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x6f,
            0x72, 0x67, 0x00, // target
            0x00, 0x01, // key 1
            0x00, 0x0c, // param length 12,
            0x08, // alpn length 8
            0x66, 0x5c, 0x6f, 0x6f, 0x2c, 0x62, 0x61, 0x72, // alpn value
            0x02, // alpn length 2
            0x68, 0x32, // alpn value
        ];
        let value = SVCB {
            priority: 16,
            target: Labels::encode("foo.example.org.").unwrap(),
            params: Some(SvcParams {
                alpn: Some(Alpn {
                    // here, it's a single \ because there's only one 0x5c and only a single 0x2c
                    // comma, neither of which need escaping in binary
                    ids: vec![r"f\oo,bar".into(), "h2".into()],
                    no_default_alpn: false,
                }),
                ..Default::default()
            }),
        };
        assert_eq!(
            SVCB::read(buf.len() as u16, &mut Cursor::new(buf)).as_ref(),
            Ok(&value)
        );

        // here, we have two levels of escaping applied,
        // - initial: [br"f\oo,bar", br"h2"]
        // - value-list encoding => f\\oo\,bar,h2
        //   this joins the values with commas, and escapes value-internal backslashes and commas
        // - char-string encoding => f\\\\oo\\,bar,h2
        let presentation = r#"16 foo.example.org. alpn=f\\\\oo\\,bar,h2"#;
        assert_eq!(value.to_string(), presentation);
    }

    #[test]
    fn test_8_again() {
        let result = Ok(ValueList {
            values: vec![br#"f\oo,bar"#.to_vec(), b"h2".to_vec()],
        });
        let result_bin = Ok(ValueList {
            values: vec![
                [0x66, 0x5c, 0x6f, 0x6f, 0x2c, 0x62, 0x61, 0x72].to_vec(),
                [0x68, 0x32].to_vec(),
            ],
        });
        // result_bin is taken directly from the binary part of the test vector
        assert_eq!(result, result_bin);
        assert_eq!(ValueList::parse(br#""f\\\\oo\\,bar,h2""#), result);
        assert_eq!(ValueList::parse(br#"f\\\092oo\092,bar,h2"#), result);
    }

    // the failure case is not useful, because we don't parse the presentation format.
}

#[cfg(test)]
mod test_ech {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn ech_param() {
        init_logs();
        let buf = &[
            0, 1,    // priority: = 1
            0x00, // target: .
            0, 1, // param: alpn
            0, 3, // param: len = 3
            2, 104, 50, // "h2"
            0, 4, // param: ipv4hint
            0, 8, // param: len = 8
            162, 159, 135, 79, // ip 1
            162, 159, 136, 79, // ip 2
            0, 5, // param: ech
            0, 72, // param: len = 72
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
            0, 6, // param: ipv6hints
            0, 32, 38, 6, 71, 0, 0, 7, 0, 0, 0, 0, 0, 0, 162, 159, 135, 79, // ipv6 1
            38, 6, 71, 0, 0, 7, 0, 0, 0, 0, 0, 0, 162, 159, 136, 79, // ipv6 2
        ];
        let parsed = SVCB::read(buf.len() as u16, &mut Cursor::new(buf));
        assert_eq!(
            parsed.map(|x| x.to_string()).as_deref(),
            Ok(
                r#"1 . alpn=h2 ipv4hint=162.159.135.79,162.159.136.79 ech=AEb+DQBCPwAgACAoJhkM1Ki3KtogKZosPZiIg3JWb8JCmnLnqs1TSGlpdwAEAAEAAQATY2xvdWRmbGFyZS1lc25pLmNvbQAA ipv6hint=2606:4700:7::a29f:874f,2606:4700:7::a29f:884f"#
            )
        );
    }
}
