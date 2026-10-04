use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// A **NAPTR** _(naming authority pointer)_ record, which holds a rule for
/// the Dynamic Delegation Discovery System.
///
/// # References
///
/// - [RFC 3403](https://tools.ietf.org/html/rfc3403) — Dynamic Delegation
///   Discovery System (DDDS) Part Three: The Domain Name System (DNS) Database
///   (October 2002)
#[derive(PartialEq, Debug)]
pub struct NAPTR {

    /// The order in which NAPTR records must be processed.
    pub order: u16,

    /// The DDDS priority.
    pub preference: u16,

    /// A set of characters that control the rewriting and interpretation of
    /// the other fields.
    pub flags: Box<[u8]>,

    /// The service parameters applicable to this delegation path.
    pub service: Box<[u8]>,

    /// A regular expression that gets applied to a string in order to
    /// construct the next domain name to look up using the DDDS algorithm.
    pub regex: Box<[u8]>,

    /// The replacement domain name as part of the DDDS algorithm.
    pub replacement: Labels,
}

impl Wire for NAPTR {
    const NAME: &'static str = "NAPTR";
    const RR_TYPE: u16 = 35;

    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let order = c.read_u16::<BigEndian>()?;
        trace!("Parsed order -> {order:?}");

        let preference = c.read_u16::<BigEndian>()?;
        trace!("Parsed preference -> {preference:?}");

        let (flags, flags_length) = read_character_string(c)?;
        trace!("Parsed flags -> {:?}", String::from_utf8_lossy(&flags));

        let (service, service_length) = read_character_string(c)?;
        trace!("Parsed service -> {:?}", String::from_utf8_lossy(&service));

        let (regex, regex_length) = read_character_string(c)?;
        trace!("Parsed regex -> {:?}", String::from_utf8_lossy(&regex));

        let (replacement, replacement_length) = c.read_labels()?;
        trace!("Parsed replacement -> {replacement:?}");

        // The two numbers, the three strings with their length bytes, and the name.
        let length_after_labels = (2 + 2 + flags_length + service_length + regex_length)
            .saturating_add(replacement_length);

        if stated_length == length_after_labels {
            Ok(Self { order, preference, flags, service, regex, replacement })
        }
        else {
            Err(WireError::WrongLabelLength { stated_length, length_after_labels })
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
            0x00, 0x05,  // order
            0x00, 0x0a,  // preference
            0x01,  // flags length
            0x73,  // flags
            0x03,  // service length
            0x53, 0x52, 0x56,  // service
            0x0e,  // regex length
            0x5c, 0x64, 0x5c, 0x64, 0x3a, 0x5c, 0x64, 0x5c, 0x64, 0x3a, 0x5c,
            0x64, 0x5c, 0x64,  // regex
            0x0b, 0x73, 0x72, 0x76, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
            0x65, 0x06, 0x6c, 0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x03, 0x64, 0x6f,
            0x67, 0x00,  // replacement
        ];

        assert_eq!(NAPTR::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)).unwrap(),
                   NAPTR {
                       order: 5,
                       preference: 10,
                       flags: Box::new(*b"s"),
                       service: Box::new(*b"SRV"),
                       regex: Box::new(*b"\\d\\d:\\d\\d:\\d\\d"),
                       replacement: Labels::encode("srv-example.lookup.dog").unwrap(),
                   });
    }

    #[test]
    fn incorrect_length() {
        let buf = &[
            0x00, 0x05,  // order
            0x00, 0x0a,  // preference
            0x01,  // flags length
            0x73,  // flags
            0x03,  // service length
            0x53, 0x52, 0x56,  // service
            0x01,  // regex length
            0x64,  // regex,
            0x00,  // replacement
        ];

        assert_eq!(NAPTR::read(11, &mut Cursor::new(buf)),
                   Err(WireError::WrongLabelLength { stated_length: 11, length_after_labels: 13 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(NAPTR::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x0A,  // order
        ];

        assert_eq!(NAPTR::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
