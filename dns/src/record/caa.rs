use crate::wire::*;


/// A **CAA** record. These allow domain names to specify which Certificate
/// Authorities are allowed to issue certificates for the domain.
///
/// # References
///
/// - [RFC 6844](https://tools.ietf.org/html/rfc6844) — DNS Certification Authority Authorization Resource Record (January 2013s
#[derive(PartialEq, Debug, Clone)]
pub struct CAA {

    /// Whether this record is marked as “critical” or not.
    pub critical: bool,

    /// The “tag” part of the CAA record.
    pub tag: String,

    /// The “value” part of the CAA record.
    pub value: String,
}

impl Wire for CAA {
    const NAME: &'static str = "CAA";
    const RR_TYPE: u16 = 257;

    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let flags = c.read_u8()?;
        let tag_length = c.read_u8()?;

        let mut tag = Vec::new();
        for _ in 0 .. tag_length {
            tag.push(c.read_u8()?);
        }

        let mut value = Vec::new();
        for _ in 0 .. len.saturating_sub(u16::from(tag_length)).saturating_sub(2) {
            value.push(c.read_u8()?);
        }

        Ok(CAA {
            critical: flags & 0b_1000_0000 == 0b_1000_0000,
            tag: String::from_utf8_lossy(&tag).to_string(),
            value: String::from_utf8_lossy(&value).to_string(),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[ 0x00, 0x09, 0x69, 0x73, 0x73, 0x75, 0x65, 0x77, 0x69,
                     0x6c, 0x64, 0x65, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74,
                     0x2e, 0x6e, 0x65, 0x74 ];

        assert_eq!(CAA::read(22, &mut Cursor::new(buf)).unwrap(),
                   CAA {
                       critical: false,
                       tag: String::from("issuewild"),
                       value: String::from("entrust.net"),
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(CAA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}
