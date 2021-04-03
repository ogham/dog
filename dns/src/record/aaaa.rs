use std::net::Ipv6Addr;

use log::*;

use crate::wire::*;


/// A **AAAA** record, which contains an `Ipv6Address`.
///
/// # References
///
/// - [RFC 3596](https://tools.ietf.org/html/rfc3596) — DNS Extensions to
///   Support IP Version 6 (October 2003)
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct AAAA {

    /// The IPv6 address contained in the packet.
    pub address: Ipv6Addr,
}

impl Wire for AAAA {
    const NAME: &'static str = "AAAA";
    const RR_TYPE: u16 = 28;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length != 16 {
            warn!("Length is incorrect (stated length {:?}, but should be sixteen)", stated_length);
            let mandated_length = MandatedLength::Exactly(16);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let mut buf = [0_u8; 16];
        c.read_exact(&mut buf)?;

        let address = Ipv6Addr::from(buf);
        trace!("Parsed IPv6 address -> {:#x?}", address);

        Ok(Self { address })
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // IPv6 address
        ];

        assert_eq!(AAAA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   AAAA { address: Ipv6Addr::new(0,0,0,0,0,0,0,0) });
    }

    #[test]
    fn record_too_long() {
        let buf = &[
            0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
            0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,  // IPv6 address
            0x09,  // Unexpected extra byte
        ];

        assert_eq!(AAAA::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 17, mandated_length: MandatedLength::Exactly(16) }));
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x05, 0x05, 0x05, 0x05, 0x05,  // Five arbitrary bytes
        ];

        assert_eq!(AAAA::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 5, mandated_length: MandatedLength::Exactly(16) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(AAAA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::Exactly(16) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x05, 0x05, 0x05, 0x05, 0x05,  // Five arbitrary bytes
        ];

        assert_eq!(AAAA::read(16, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
