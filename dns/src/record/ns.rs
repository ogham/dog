use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// A **NS** _(name server)_ record, which is used to point domains to name
/// servers.
///
/// # References
///
/// - [RFC 1035 §3.3.11](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
#[derive(PartialEq, Debug)]
pub struct NS {

    /// The address of a nameserver that provides this DNS response.
    pub nameserver: Labels,
}

impl Wire for NS {
    const NAME: &'static str = "NS";
    const RR_TYPE: u16 = 2;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let (nameserver, nameserver_length) = c.read_labels()?;
        trace!("Parsed nameserver -> {:?}", nameserver);

        if stated_length == nameserver_length {
            trace!("Length is correct");
            Ok(Self { nameserver })
        }
        else {
            warn!("Length is incorrect (stated length {:?}, nameserver length {:?}", stated_length, nameserver_length);
            Err(WireError::WrongLabelLength { stated_length, length_after_labels: nameserver_length })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x01, 0x61, 0x0c, 0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72,
            0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74,  // nameserver
            0x00,  // nameserver terminator
        ];

        assert_eq!(NS::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   NS {
                       nameserver: Labels::encode("a.gtld-servers.net").unwrap(),
                   });
    }

    #[test]
    fn incorrect_record_length() {
        let buf = &[
            0x03, 0x65, 0x66, 0x67,  // nameserver
            0x00,  // nameserver terminator
        ];

        assert_eq!(NS::read(66, &mut Cursor::new(buf)),
                   Err(WireError::WrongLabelLength { stated_length: 66, length_after_labels: 5 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(NS::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x01,  // the first byte of a string
        ];

        assert_eq!(NS::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
