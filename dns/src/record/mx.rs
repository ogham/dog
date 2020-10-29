use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// An **MX** _(mail exchange)_ record, which contains the hostnames for mail
/// servers that handle mail sent to the domain.
///
/// # References
///
/// - [RFC 1035 §3.3.s](https://tools.ietf.org/html/rfc1035) — Domain Names, Implementation and Specification (November 1987)
#[derive(PartialEq, Debug)]
pub struct MX {

    /// The preference that clients should give to this MX record amongst all
    /// that get returned.
    pub preference: u16,

    /// The domain name of the mail exchange server.
    pub exchange: Labels,
}

impl Wire for MX {
    const NAME: &'static str = "MX";
    const RR_TYPE: u16 = 15;

    #[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let preference = c.read_u16::<BigEndian>()?;
        trace!("Parsed preference -> {:?}", preference);

        let (exchange, exchange_len) = c.read_labels()?;
        trace!("Parsed exchange -> {:?}", exchange);

        let got_len = 2 + exchange_len;
        if len == got_len {
            trace!("Length is correct");
            Ok(Self { preference, exchange })
        }
        else {
            warn!("Length is incorrect (record length {:?}, preference plus exchange length {:?}", len, got_len);
            Err(WireError::WrongLabelLength { expected: len, got: got_len })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x0A,  // preference
            0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65,  // exchange
            0x00,  // exchange terminator
        ];

        assert_eq!(MX::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   MX {
                       preference: 10,
                       exchange: Labels::encode("bsago.me").unwrap(),
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(MX::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x0A,  // half a preference
        ];

        assert_eq!(MX::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
