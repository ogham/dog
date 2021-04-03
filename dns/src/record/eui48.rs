use log::*;

use crate::wire::*;


/// A **EUI48** record, which holds a six-octet (48-bit) Extended Unique
/// Identifier. These identifiers can be used as MAC addresses.
///
/// # References
///
/// - [RFC 7043](https://tools.ietf.org/html/rfc7043) — Resource Records for
///   EUI-48 and EUI-64 Addresses in the DNS (October 2013)
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct EUI48 {

    /// The six octets that make up the identifier.
    pub octets: [u8; 6],
}

impl Wire for EUI48 {
    const NAME: &'static str = "EUI48";
    const RR_TYPE: u16 = 108;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length != 6 {
            warn!("Length is incorrect (record length {:?}, but should be six)", stated_length);
            let mandated_length = MandatedLength::Exactly(6);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let mut octets = [0_u8; 6];
        c.read_exact(&mut octets)?;
        trace!("Parsed 6-byte address -> {:#x?}", octets);

        Ok(Self { octets })
    }
}


impl EUI48 {

    /// Returns this EUI as hexadecimal numbers, separated by dashes.
    pub fn formatted_address(self) -> String {
        format!("{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}",
                self.octets[0], self.octets[1], self.octets[2],
                self.octets[3], self.octets[4], self.octets[5])
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x7F, 0x23, 0x12, 0x34, 0x56,  // identifier
        ];

        assert_eq!(EUI48::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   EUI48 { octets: [ 0x00, 0x7F, 0x23, 0x12, 0x34, 0x56 ] });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00, 0x7F, 0x23,  // a mere OUI
        ];

        assert_eq!(EUI48::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 3, mandated_length: MandatedLength::Exactly(6) }));
    }

    #[test]
    fn record_too_long() {
        let buf = &[
            0x00, 0x7F, 0x23, 0x12, 0x34, 0x56,  // identifier
            0x01,  // an unexpected extra byte
        ];

        assert_eq!(EUI48::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 7, mandated_length: MandatedLength::Exactly(6) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(EUI48::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::Exactly(6) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x7F, 0x23,  // a mere OUI
        ];

        assert_eq!(EUI48::read(6, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn hex_rep() {
        let record = EUI48 { octets: [ 0x00, 0x7F, 0x23, 0x12, 0x34, 0x56 ] };

        assert_eq!(record.formatted_address(),
                   "00-7f-23-12-34-56");
    }
}
