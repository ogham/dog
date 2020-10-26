use log::*;

use crate::strings::ReadLabels;
use crate::wire::*;


/// A **CNAME** _(canonical name)_ record, which aliases one domain to another.
///
/// # References
///
/// - [RFC 1035 §3.3.1](https://tools.ietf.org/html/rfc1035) — Domain Names, Implementation and Specification (November 1987)
#[derive(PartialEq, Debug, Clone)]
pub struct CNAME {

    /// The domain name that this CNAME record is responding with.
    pub domain: String,
}

impl Wire for CNAME {
    const NAME: &'static str = "CNAME";
    const RR_TYPE: u16 = 5;

    #[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let (domain, domain_len) = c.read_labels()?;
        trace!("Parsed domain -> {:?}", domain);

        if len == domain_len {
            trace!("Length is correct");
            Ok(Self { domain })
        }
        else {
            warn!("Length is incorrect (record length {:?}, domain length {:?})", len, domain_len);
            Err(WireError::WrongLabelLength { expected: len, got: domain_len })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65,  // domain
            0x00,  // domain terminator
        ];

        assert_eq!(CNAME::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   CNAME {
                       domain: String::from("bsago.me."),
                   });
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

