use std::net::Ipv6Addr;

use crate::wire::*;


/// A **AAAA** record, which contains an `Ipv6Address`.
///
/// # References
///
/// - [RFC 3596](https://tools.ietf.org/html/rfc3596) — DNS Extensions to Support IP Version 6 (October 2003)
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct AAAA {

    /// The IPv6 address contained in the packet.
    pub address: Ipv6Addr,
}

impl Wire for AAAA {
    const NAME: &'static str = "AAAA";
    const RR_TYPE: u16 = 28;

    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let mut buf = Vec::new();
        for _ in 0 .. len {
            buf.push(c.read_u8()?);
        }

        if let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = *buf {
            let address = Ipv6Addr::from([a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]);
            // probably the best two lines of code I have ever written
            Ok(AAAA { address })
        }
        else {
            Err(WireError::WrongLength { expected: 16, got: buf.len() as u16 })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[ 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 ];

        assert_eq!(AAAA::read(16, &mut Cursor::new(buf)).unwrap(),
                   AAAA { address: Ipv6Addr::new(0,0,0,0,0,0,0,0) });
    }

    #[test]
    fn too_long() {
        let buf = &[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9];

        assert_eq!(AAAA::read(19, &mut Cursor::new(buf)),
                   Err(WireError::WrongLength { expected: 16, got: 19 }));
    }

    #[test]
    fn too_empty() {
        let buf = &[];

        assert_eq!(AAAA::read(0, &mut Cursor::new(buf)),
                   Err(WireError::WrongLength { expected: 16, got: 0 }));
    }

    #[test]
    fn too_short() {
        let buf = &[ 5,5,5,5,5 ];

        assert_eq!(AAAA::read(5, &mut Cursor::new(buf)),
                   Err(WireError::WrongLength { expected: 16, got: 5 }));
    }

    #[test]
    fn empty() {
        assert_eq!(AAAA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongLength { expected: 16, got: 0 }));
    }
}
