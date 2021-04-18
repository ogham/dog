use log::*;

use crate::wire::*;


/// A **CAA** _(certification authority authorization)_ record. These allow
/// domain names to specify which Certificate Authorities are allowed to issue
/// certificates for the domain.
///
/// # References
///
/// - [RFC 6844](https://tools.ietf.org/html/rfc6844) — DNS Certification
///   Authority Authorization Resource Record (January 2013)
#[derive(PartialEq, Debug)]
pub struct CAA {

    /// Whether this record is marked as “critical” or not.
    pub critical: bool,

    /// The “tag” part of the CAA record.
    pub tag: Box<[u8]>,

    /// The “value” part of the CAA record.
    pub value: Box<[u8]>,
}

impl Wire for CAA {
    const NAME: &'static str = "CAA";
    const RR_TYPE: u16 = 257;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {

        // flags
        let flags = c.read_u8()?;
        trace!("Parsed flags -> {:#08b}", flags);

        let has_bit = |bit| { flags & bit == bit };
        let critical = has_bit(0b_1000_0000);
        trace!("Parsed critical flag -> {:?}", critical);

        // tag
        let tag_length = c.read_u8()?;
        trace!("Parsed tag length -> {:?}", tag_length);

        let mut tag = vec![0_u8; usize::from(tag_length)].into_boxed_slice();
        c.read_exact(&mut tag)?;
        trace!("Parsed tag -> {:?}", String::from_utf8_lossy(&tag));

        // value
        let remaining_length = stated_length.saturating_sub(u16::from(tag_length)).saturating_sub(2);
        trace!("Remaining length -> {:?}", remaining_length);

        let mut value = vec![0_u8; usize::from(remaining_length)].into_boxed_slice();
        c.read_exact(&mut value)?;
        trace!("Parsed value -> {:?}", String::from_utf8_lossy(&value));

        Ok(Self { critical, tag, value })
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_non_critical() {
        let buf = &[
            0x00,  // flags (all unset)
            0x09,  // tag length
            0x69, 0x73, 0x73, 0x75, 0x65, 0x77, 0x69, 0x6c, 0x64,  // tag
            0x65, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74,  // value
        ];

        assert_eq!(CAA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   CAA {
                       critical: false,
                       tag: Box::new(*b"issuewild"),
                       value: Box::new(*b"entrust.net"),
                   });
    }

    #[test]
    fn parses_critical() {
        let buf = &[
            0x80,  // flags (critical bit set)
            0x09,  // tag length
            0x69, 0x73, 0x73, 0x75, 0x65, 0x77, 0x69, 0x6c, 0x64,  // tag
            0x65, 0x6e, 0x74, 0x72, 0x75, 0x73, 0x74, 0x2e, 0x6e, 0x65, 0x74,  // value
        ];

        assert_eq!(CAA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   CAA {
                       critical: true,
                       tag: Box::new(*b"issuewild"),
                       value: Box::new(*b"entrust.net"),
                   });
    }

    #[test]
    fn ignores_other_flags() {
        let buf = &[
            0x7F,  // flags (all except critical bit set)
            0x01,  // tag length
            0x65,  // tag
            0x45,  // value
        ];

        assert_eq!(CAA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   CAA {
                       critical: false,
                       tag: Box::new(*b"e"),
                       value: Box::new(*b"E"),
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(CAA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00,  // flags
        ];

        assert_eq!(CAA::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
