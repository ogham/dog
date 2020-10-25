use log::*;

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

    #[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let flags = c.read_u8()?;
        trace!("Parsed flags -> {:#08b}", flags);

        let critical = flags & 0b_1000_0000 == 0b_1000_0000;
        trace!("Parsed critical flag -> {:?}", critical);

        let tag_length = c.read_u8()?;
        trace!("Parsed tag length -> {:?}", tag_length);

        let mut tag_buf = Vec::new();
        for _ in 0 .. tag_length {
            tag_buf.push(c.read_u8()?);
        }

        let tag = String::from_utf8_lossy(&tag_buf).to_string();
        trace!("Parsed tag -> {:?}", tag);

        let remaining_length = len.saturating_sub(u16::from(tag_length)).saturating_sub(2);
        trace!("Remaining length -> {:?}", remaining_length);

        let mut value_buf = Vec::new();
        for _ in 0 .. remaining_length {
            value_buf.push(c.read_u8()?);
        }

        let value = String::from_utf8_lossy(&value_buf).to_string();
        trace!("Parsed value -> {:?}", value);

        let got_len = 1 + 1 + u16::from(tag_length) + remaining_length;
        if len == got_len {
            // This one’s a little weird, because remaining_len is based on len
            trace!("Length is correct");
            Ok(Self { critical, tag, value })
        }
        else {
            warn!("Length is incorrect (record length {:?}, flags plus tag plus data length {:?}", len, got_len);
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
            0x00,  // flags
            0x09,  // tag length
            0x69, 0x73, 0x73, 0x75, 0x65, 0x77, 0x69, 0x6c, 0x64,  // tag
            0x65, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74,  // value
        ];

        assert_eq!(CAA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
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
