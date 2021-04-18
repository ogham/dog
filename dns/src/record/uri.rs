use log::*;

use crate::wire::*;


/// A **URI** record, which holds a URI along with weight and priority values
/// to balance between several records.
///
/// # References
///
/// - [RFC 7553](https://tools.ietf.org/html/rfc7553) — The Uniform Resource
///   Identifier (URI) DNS Resource Record (June 2015)
/// - [RFC 3986](https://tools.ietf.org/html/rfc3986) — Uniform Resource
///   Identifier (URI): Generic Syntax (January 2005)
#[derive(PartialEq, Debug)]
pub struct URI {

    /// The priority of the URI. Clients are supposed to contact the URI with
    /// the lowest priority out of all the ones it can reach.
    pub priority: u16,

    /// The weight of the URI, which specifies a relative weight for entries
    /// with the same priority.
    pub weight: u16,

    /// The URI contained in the record. Since all we are doing is displaying
    /// it to the user, we do not need to parse it for accuracy.
    pub target: Box<[u8]>,
}

impl Wire for URI {
    const NAME: &'static str = "URI";
    const RR_TYPE: u16 = 256;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let priority = c.read_u16::<BigEndian>()?;
        trace!("Parsed priority -> {:?}", priority);

        let weight = c.read_u16::<BigEndian>()?;
        trace!("Parsed weight -> {:?}", weight);

        // The target must not be empty.
        if stated_length <= 4 {
            let mandated_length = MandatedLength::AtLeast(5);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let remaining_length = stated_length - 4;
        let mut target = vec![0_u8; usize::from(remaining_length)].into_boxed_slice();
        c.read_exact(&mut target)?;
        trace!("Parsed target -> {:?}", String::from_utf8_lossy(&target));

        Ok(Self { priority, weight, target })
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x0A,  // priority
            0x00, 0x10,  // weight
            0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x72, 0x66, 0x63,
            0x73, 0x2e, 0x69, 0x6f, 0x2f,  // uri
        ];

        assert_eq!(URI::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   URI {
                       priority: 10,
                       weight: 16,
                       target: Box::new(*b"https://rfcs.io/"),
                   });
    }

    #[test]
    fn one_byte_of_uri() {
        let buf = &[
            0x00, 0x0A,  // priority
            0x00, 0x10,  // weight
            0x2f,  // one byte of uri (invalid but still a legitimate DNS record)
        ];

        assert_eq!(URI::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   URI {
                       priority: 10,
                       weight: 16,
                       target: Box::new(*b"/"),
                   });
    }

    #[test]
    fn missing_any_data() {
        let buf = &[
            0x00, 0x0A,  // priority
            0x00, 0x10,  // weight
        ];

        assert_eq!(URI::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 4, mandated_length: MandatedLength::AtLeast(5) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(URI::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x0A,  // half a priority
        ];

        assert_eq!(URI::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
