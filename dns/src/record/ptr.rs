use crate::strings::ReadLabels;
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
/// - [RFC 1035 §3.3.14](https://tools.ietf.org/html/rfc1035) — Domain Names, Implementation and Specification (November 1987)
#[derive(PartialEq, Debug, Clone)]
pub struct PTR {

    /// The CNAME contained in the record.
    pub cname: String,
}

impl Wire for PTR {
    const NAME: &'static str = "PTR";
    const RR_TYPE: u16 = 12;

    fn read(_len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let cname = c.read_labels()?;
        Ok(PTR { cname })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[ 0x03, 0x64, 0x6e, 0x73, 0x06, 0x67,
                     0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x00 ];

        assert_eq!(PTR::read(12, &mut Cursor::new(buf)).unwrap(),
                   PTR {
                       cname: String::from("dns.google."),
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(PTR::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}
