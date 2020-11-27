use std::net::Ipv4Addr;

use log::*;

use crate::wire::*;


/// An **A** record type, which contains an `Ipv4Address`.
///
/// # References
///
/// - [RFC 1035 §3.4.1](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct A {

    /// The IPv4 address contained in the packet.
    pub address: Ipv4Addr,
}

impl Wire for A {
    const NAME: &'static str = "A";
    const RR_TYPE: u16 = 1;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length != 4 {
            warn!("Length is incorrect (record length {:?}, but should be four)", stated_length);
            let mandated_length = MandatedLength::Exactly(4);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let mut buf = [0_u8; 4];
        c.read_exact(&mut buf)?;

        let address = Ipv4Addr::from(buf);
        trace!("Parsed IPv4 address -> {:?}", address);

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
            0x7F, 0x00, 0x00, 0x01,  // IPv4 address
        ];

        assert_eq!(A::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   A { address: Ipv4Addr::new(127, 0, 0, 1) });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x7F, 0x00, 0x00,  // Too short IPv4 address
        ];

        assert_eq!(A::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 3, mandated_length: MandatedLength::Exactly(4) }));
    }

    #[test]
    fn record_too_long() {
        let buf = &[
            0x7F, 0x00, 0x00, 0x00,  // IPv4 address
            0x01,  // Unexpected extra byte
        ];

        assert_eq!(A::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 5, mandated_length: MandatedLength::Exactly(4) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(A::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::Exactly(4) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x7F, 0x00,  // Half an IPv4 address
        ];

        assert_eq!(A::read(4, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
