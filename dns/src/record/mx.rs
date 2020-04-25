use crate::strings::ReadLabels;
use crate::wire::*;

use log::{warn, debug};


/// An **MX** _(mail exchange)_ record, which contains the hostnames for mail
/// servers that handle mail sent to the domain.
///
/// # References
///
/// - [RFC 1035 §3.3.s](https://tools.ietf.org/html/rfc1035) — Domain Names, Implementation and Specification (November 1987)
#[derive(PartialEq, Debug, Clone)]
pub struct MX {

    /// The preference that clients should give to this MX record amongst all
    /// that get returned.
    pub preference: u16,

    /// The domain name of the mail exchange server.
    pub exchange: String,
}

impl Wire for MX {
    const NAME: &'static str = "MX";
    const RR_TYPE: u16 = 15;

    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let preference = c.read_u16::<BigEndian>()?;
        let exchange = c.read_labels()?;

        if 2 + exchange.len() + 1 != len as usize {
            warn!("Expected length {} but read {} bytes", len, 2 + exchange.len() + 1);
        }
        else {
            debug!("Length {} is correct", len);
        }

        Ok(MX { preference, exchange })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[ 0x00, 0x0A, 0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02,
                     0x6d, 0x65, 0x00 ];

        assert_eq!(MX::read(12, &mut Cursor::new(buf)).unwrap(),
                   MX {
                       preference: 10,
                       exchange: String::from("bsago.me."),
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(MX::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}
