use log::*;

use crate::wire::*;


/// A **DNSKEY** _(DNS key)_ record, which holds a public key used for DNSSEC.
///
/// # References
///
/// - [RFC 4034 §2](https://tools.ietf.org/html/rfc4034#section-2) — Resource
///   Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct DNSKEY {

    /// Flags field. Bit 7 is the Zone Key flag, bit 15 is the Secure Entry
    /// Point (SEP) flag. A value of 256 means Zone Key, 257 means Zone Key
    /// with SEP (typically a KSK).
    pub flags: u16,

    /// Protocol field. Must always be 3 for DNSSEC.
    pub protocol: u8,

    /// The algorithm number used for the key.
    pub algorithm: u8,

    /// The public key material.
    pub public_key: Vec<u8>,
}

impl Wire for DNSKEY {
    const NAME: &'static str = "DNSKEY";
    const RR_TYPE: u16 = 48;

    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length < 4 {
            let mandated_length = MandatedLength::AtLeast(4);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let flags = c.read_u16::<BigEndian>()?;
        trace!("Parsed flags -> {flags:?}");

        let protocol = c.read_u8()?;
        trace!("Parsed protocol -> {protocol:?}");

        let algorithm = c.read_u8()?;
        trace!("Parsed algorithm -> {algorithm:?}");

        let key_length = stated_length - 4;
        let mut public_key = vec![0_u8; usize::from(key_length)];
        c.read_exact(&mut public_key)?;
        trace!("Parsed public key -> {public_key:#x?}");

        Ok(Self { flags, protocol, algorithm, public_key })
    }
}

impl DNSKEY {

    /// Returns the base64-encoded public key.
    pub fn base64_public_key(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&self.public_key)
    }

    /// Returns a human-readable name for the algorithm number, if known.
    pub fn algorithm_name(&self) -> Option<&'static str> {
        super::registry::dnssec_algorithm_name(self.algorithm)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x01, 0x01,  // flags (257 = KSK)
            0x03,        // protocol
            0x0D,        // algorithm (13 = ECDSAP256SHA256)
            0x99, 0xDB, 0x2C, 0xC9,  // public key (abbreviated)
        ];

        assert_eq!(DNSKEY::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)).unwrap(),
                   DNSKEY {
                       flags: 257,
                       protocol: 3,
                       algorithm: 13,
                       public_key: vec![ 0x99, 0xDB, 0x2C, 0xC9 ],
                   });
    }

    #[test]
    fn parses_zone_key() {
        let buf = &[
            0x01, 0x00,  // flags (256 = ZSK)
            0x03,        // protocol
            0x08,        // algorithm (8 = RSASHA256)
            0xAA, 0xBB,  // public key
        ];

        assert_eq!(DNSKEY::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)).unwrap(),
                   DNSKEY {
                       flags: 256,
                       protocol: 3,
                       algorithm: 8,
                       public_key: vec![ 0xAA, 0xBB ],
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x01, 0x01,  // flags
            0x03,        // protocol, but no algorithm
        ];

        assert_eq!(DNSKEY::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 3, mandated_length: MandatedLength::AtLeast(4) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(DNSKEY::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::AtLeast(4) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x01, 0x01,  // flags
        ];

        assert_eq!(DNSKEY::read(8, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn base64_key() {
        let dnskey = DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![ 0x99, 0xDB, 0x2C, 0xC9 ],
        };

        assert_eq!(dnskey.base64_public_key(),
                   String::from("mdssyQ=="));
    }

    #[test]
    fn known_algorithm_name() {
        let dnskey = DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: vec![],
        };

        assert_eq!(dnskey.algorithm_name(), Some("ECDSAP256SHA256"));
    }

    #[test]
    fn unknown_algorithm_name() {
        let dnskey = DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 99,
            public_key: vec![],
        };

        assert_eq!(dnskey.algorithm_name(), None);
    }
}
