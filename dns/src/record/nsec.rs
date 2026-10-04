use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// An **NSEC** _(next secure)_ record, which is used in DNSSEC to prove the
/// non-existence of a domain name. It lists the next owner name in the zone
/// and the set of record types that exist at the NSEC owner name.
///
/// # References
///
/// - [RFC 4034 §4](https://tools.ietf.org/html/rfc4034#section-4) — Resource
///   Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct NSEC {

    /// The next owner name in the canonical ordering of the zone.
    pub next_domain: Labels,

    /// The set of record type numbers that exist at the NSEC owner name,
    /// decoded from the type bit maps.
    pub types: Vec<u16>,
}

impl Wire for NSEC {
    const NAME: &'static str = "NSEC";
    const RR_TYPE: u16 = 47;

    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length < 2 {
            let mandated_length = MandatedLength::AtLeast(2);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let (next_domain, next_domain_length) = c.read_labels()?;
        trace!("Parsed next domain -> {next_domain:?}");

        // A record whose stated length is shorter than its own name is
        // malformed; subtracting blindly would underflow.
        let bitmap_length = stated_length.checked_sub(next_domain_length)
            .ok_or(WireError::WrongLabelLength { stated_length, length_after_labels: next_domain_length })?;
        let mut bitmap_bytes = vec![0_u8; usize::from(bitmap_length)];
        c.read_exact(&mut bitmap_bytes)?;
        trace!("Parsed type bitmap -> {bitmap_bytes:#x?}");

        let types = parse_type_bitmaps(&bitmap_bytes);
        trace!("Parsed types -> {types:?}");

        Ok(Self { next_domain, types })
    }
}

/// Parses the type bit maps format used by NSEC and NSEC3 records.
///
/// The format is: one or more windows, each consisting of:
/// - Window block number (1 byte)
/// - Bitmap length (1 byte, 1-32)
/// - Bitmap (variable, up to 32 bytes)
///
/// Each bit in the bitmap represents a record type. Window block N covers
/// types N*256 through N*256+255.
fn parse_type_bitmaps(data: &[u8]) -> Vec<u16> {
    let mut types = Vec::new();
    let mut i = 0;

    while i + 1 < data.len() {
        let window = u16::from(data[i]);
        let bitmap_len = usize::from(data[i + 1]);
        i += 2;

        if bitmap_len == 0 || bitmap_len > 32 || i + bitmap_len > data.len() {
            break;
        }

        // At most 255 × 256 + 31 × 8 + 7 = 65535, so this never overflows.
        for (byte_idx, &byte) in (0_u16 ..).zip(&data[i .. i + bitmap_len]) {
            for bit in 0 .. 8 {
                if byte & (0x80 >> bit) != 0 {
                    types.push(window * 256 + byte_idx * 8 + bit);
                }
            }
        }

        i += bitmap_len;
    }

    types
}

impl NSEC {

    /// Returns human-readable names for the type numbers in this record,
    /// using the RFC 3597 form `TYPEnnn` for types that have no name.
    pub fn type_names(&self) -> Vec<String> {
        self.types.iter()
            .map(|&number| match super::registry::record_type_name(number) {
                Some(name) => name.to_owned(),
                None       => format!("TYPE{number}"),
            })
            .collect()
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        // next_domain = "beta.example.com", types = A(1), RRSIG(46), NSEC(47)
        // Type 1:  byte 0, bit 1 -> 0x40
        // Type 46: byte 5, bit 6 -> 0x02
        // Type 47: byte 5, bit 7 -> 0x01 => byte 5 = 0x03
        let buf = &[
            0x04, 0x62, 0x65, 0x74, 0x61,  // "beta"
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,  // "example"
            0x03, 0x63, 0x6F, 0x6D,  // "com"
            0x00,        // terminator
            0x00, 0x06,  // window 0, bitmap length 6
            0x40,        // byte 0: A(1)
            0x00,        // byte 1
            0x00,        // byte 2
            0x00,        // byte 3
            0x00,        // byte 4
            0x03,        // byte 5: RRSIG(46), NSEC(47)
        ];

        assert_eq!(NSEC::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)).unwrap(),
                   NSEC {
                       next_domain: Labels::encode("beta.example.com").unwrap(),
                       types: vec![1, 46, 47],
                   });
    }

    #[test]
    fn parses_multiple_types() {
        // next_domain = root ".", types = A(1), NS(2), SOA(6), MX(15), TXT(16)
        // Type 1:  byte 0, bit 1 -> 0x40
        // Type 2:  byte 0, bit 2 -> 0x20
        // Type 6:  byte 0, bit 6 -> 0x02 => byte 0 = 0x62
        // Type 15: byte 1, bit 7 -> 0x01
        // Type 16: byte 2, bit 0 -> 0x80
        let buf = &[
            0x00,        // root label
            0x00, 0x03,  // window 0, bitmap length 3
            0x62,        // byte 0: A(1), NS(2), SOA(6)
            0x01,        // byte 1: MX(15)
            0x80,        // byte 2: TXT(16)
        ];

        assert_eq!(NSEC::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)).unwrap(),
                   NSEC {
                       next_domain: Labels::encode(".").unwrap(),
                       types: vec![1, 2, 6, 15, 16],
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00,  // just a root label, no bitmap
        ];

        assert_eq!(NSEC::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 1, mandated_length: MandatedLength::AtLeast(2) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(NSEC::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::AtLeast(2) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x04, 0x74,  // start of a label
        ];

        assert_eq!(NSEC::read(10, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn type_names_known() {
        let nsec = NSEC {
            next_domain: Labels::encode("example.com").unwrap(),
            types: vec![1, 2, 6, 15, 28, 46, 47, 48],
        };

        assert_eq!(nsec.type_names(),
                   vec!["A", "NS", "SOA", "MX", "AAAA", "RRSIG", "NSEC", "DNSKEY"]);
    }

    #[test]
    fn type_names_unknown() {
        let nsec = NSEC {
            next_domain: Labels::encode("example.com").unwrap(),
            types: vec![1, 9999],
        };

        assert_eq!(nsec.type_names(),
                   vec!["A", "TYPE9999"]);
    }

    #[test]
    fn parse_bitmap_empty() {
        assert_eq!(parse_type_bitmaps(&[]), Vec::<u16>::new());
    }

    #[test]
    fn parse_bitmap_single_type() {
        // Window 0, length 1, byte = 0x40 -> type 1 (A)
        let bitmap = &[0x00, 0x01, 0x40];
        assert_eq!(parse_type_bitmaps(bitmap), vec![1]);
    }
}
