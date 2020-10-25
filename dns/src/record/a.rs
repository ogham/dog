use std::net::Ipv4Addr;

use log::*;

use crate::wire::*;


/// An **A** record type, which contains an `Ipv4Address`.
///
/// # References
///
/// - [RFC 1035 §3.4.1](https://tools.ietf.org/html/rfc1035) — Domain Names, Implementation and Specification (November 1987)
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct A {

    /// The IPv4 address contained in the packet.
    pub address: Ipv4Addr,
}

impl Wire for A {
    const NAME: &'static str = "A";
    const RR_TYPE: u16 = 1;

    #[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let mut buf = Vec::new();
        for _ in 0 .. len {
            buf.push(c.read_u8()?);
        }

        if let [a, b, c, d] = *buf {
            let address = Ipv4Addr::new(a, b, c, d);
            trace!("Parsed IPv4 address -> {:?}", address);
            Ok(Self { address })
        }
        else {
            warn!("Length is incorrect (record length {:?}, but should be four)", len);
            Err(WireError::WrongRecordLength { expected: 4, got: buf.len() as u16 })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x7F, 0x00, 0x00, 0x01,  // IPv4 address
        ];

        assert_eq!(A::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   A { address: Ipv4Addr::new(127, 0, 0, 1) });
    }

    #[test]
    fn too_short() {
        let buf = &[
            0x7F, 0x00, 0x00,  // Too short IPv4 address
        ];

        assert_eq!(A::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { expected: 4, got: 3 }));
    }

    #[test]
    fn too_long() {
        let buf = &[
            0x7F, 0x00, 0x00, 0x00,  // IPv4 address
            0x01,  // Unexpected extra byte
        ];

        assert_eq!(A::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { expected: 4, got: 5 }));
    }

    #[test]
    fn empty() {
        assert_eq!(A::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { expected: 4, got: 0 }));
    }
}
