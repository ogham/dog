use log::*;

use crate::wire::*;

/// A **EUI64** record, which holds an eight-octet (64-bit) Extended Unique
/// Identifier.
///
/// # References
///
/// - [RFC 7043](https://tools.ietf.org/html/rfc7043) — Resource Records for
///   EUI-48 and EUI-64 Addresses in the DNS (October 2013)
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EUI64 {

    /// The eight octets that make up the identifier.
    pub octets: [u8; 8],
}

impl Wire for EUI64 {
    const NAME: &'static str = "EUI64";
    const RR_TYPE: u16 = 109;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length != 8 {
            warn!("Length is incorrect (record length {:?}, but should be eight)", stated_length);
            let mandated_length = MandatedLength::Exactly(8);
            return Err(WireError::wrong_record_length(stated_length, mandated_length));
        }

        let mut octets = [0_u8; 8];
        c.read_exact(&mut octets)?;

        Ok(Self { octets })
    }
}


impl EUI64 {

    /// Returns this EUI as hexadecimal numbers, separated by dashes.
    pub fn formatted_address(&self) -> String {
        format!("{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                self.octets[0], self.octets[1], self.octets[2], self.octets[3],
                self.octets[4], self.octets[5], self.octets[6], self.octets[7])
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x7F, 0x23, 0x12, 0x34, 0x56, 0x78, 0x90,  // identifier
        ];

        assert_eq!(EUI64::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   EUI64 { octets: [ 0x00, 0x7F, 0x23, 0x12, 0x34, 0x56, 0x78, 0x90 ] });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00, 0x7F, 0x23,  // a mere OUI
        ];

        assert_eq!(EUI64::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::wrong_record_length(3, MandatedLength::Exactly(8))));
    }

    #[test]
    fn record_too_long() {
        let buf = &[
            0x00, 0x7F, 0x23, 0x12, 0x34, 0x56, 0x78, 0x90,  // identifier
            0x01,  // an unexpected extra byte
        ];

        assert_eq!(EUI64::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::wrong_record_length(9, MandatedLength::Exactly(8))));
    }

    #[test]
    fn record_empty() {
        assert_eq!(EUI64::read(0, &mut Cursor::new(&[])),
                   Err(WireError::wrong_record_length(0, MandatedLength::Exactly(8))));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x7F, 0x23,  // a mere OUI
        ];

        assert_eq!(EUI64::read(8, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn hex_rep() {
        let record = EUI64 { octets: [ 0x00, 0x7F, 0x23, 0x12, 0x34, 0x56, 0x78, 0x90 ] };

        assert_eq!(record.formatted_address(),
                   "00-7f-23-12-34-56-78-90");
    }
}
