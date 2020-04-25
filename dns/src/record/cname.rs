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

    fn read(_len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let domain = c.read_labels()?;
        Ok(CNAME { domain })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[ 0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65, 0x00, ];

        assert_eq!(CNAME::read(10, &mut Cursor::new(buf)).unwrap(),
                   CNAME {
                       domain: String::from("bsago.me."),
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(CNAME::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}

