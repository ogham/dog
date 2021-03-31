use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// A **CNAME** _(canonical name)_ record, which aliases one domain to another.
///
/// # References
///
/// - [RFC 1035 §3.3.1](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
#[derive(PartialEq, Debug)]
pub struct CNAME {

    /// The domain name that this CNAME record is responding with.
    pub domain: Labels,
}

impl Wire for CNAME {
    const NAME: &'static str = "CNAME";
    const RR_TYPE: u16 = 5;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let (domain, domain_length) = c.read_labels()?;
        trace!("Parsed domain -> {:?}", domain);

        if stated_length == domain_length {
            trace!("Length is correct");
            Ok(Self { domain })
        }
        else {
            warn!("Length is incorrect (stated length {:?}, domain length {:?})", stated_length, domain_length);
            Err(WireError::WrongLabelLength { stated_length, length_after_labels: domain_length })
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
            0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65,  // domain
            0x00,  // domain terminator
        ];

        assert_eq!(CNAME::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   CNAME {
                       domain: Labels::encode("bsago.me").unwrap(),
                   });
    }

    #[test]
    fn incorrect_record_length() {
        let buf = &[
            0x03, 0x65, 0x66, 0x67,  // domain
            0x00,  // domain terminator
        ];

        assert_eq!(CNAME::read(6, &mut Cursor::new(buf)),
                   Err(WireError::WrongLabelLength { stated_length: 6, length_after_labels: 5 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(CNAME::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x05, 0x62, 0x73,  // the stard of a string
        ];

        assert_eq!(CNAME::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}

