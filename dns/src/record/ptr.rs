use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// A **PTR** record, which holds a _pointer_ to a canonical name. This is
/// most often used for reverse DNS lookups.
///
/// # Encoding
///
/// The text encoding is not specified, but this crate treats it as UTF-8.
/// Invalid bytes are turned into the replacement character.
///
/// # References
///
/// - [RFC 1035 §3.3.14](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
#[derive(PartialEq, Debug)]
pub struct PTR {

    /// The CNAME contained in the record.
    pub cname: Labels,
}

impl Wire for PTR {
    const NAME: &'static str = "PTR";
    const RR_TYPE: u16 = 12;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let (cname, cname_length) = c.read_labels()?;
        trace!("Parsed cname -> {:?}", cname);

        if stated_length == cname_length {
            trace!("Length is correct");
            Ok(Self { cname })
        }
        else {
            warn!("Length is incorrect (stated length {:?}, cname length {:?}", stated_length, cname_length);
            Err(WireError::WrongLabelLength { stated_length, length_after_labels: cname_length })
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
            0x03, 0x64, 0x6e, 0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  // cname
            0x00,  // cname terminator
        ];

        assert_eq!(PTR::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   PTR {
                       cname: Labels::encode("dns.google").unwrap(),
                   });
    }

    #[test]
    fn incorrect_record_length() {
        let buf = &[
            0x03, 0x65, 0x66, 0x67,  // cname
            0x00,  // cname terminator
        ];

        assert_eq!(PTR::read(6, &mut Cursor::new(buf)),
                   Err(WireError::WrongLabelLength { stated_length: 6, length_after_labels: 5 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(PTR::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x03, 0x64,  // the start of a cname
        ];

        assert_eq!(PTR::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
