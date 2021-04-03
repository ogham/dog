use log::*;

use crate::wire::*;


/// A **OPENPGPKEY** record, which holds a PGP key.
///
/// # References
///
/// - [RFC 1035 §3.3.14](https://tools.ietf.org/html/rfc7929) — DNS-Based
///   Authentication of Named Entities Bindings for OpenPGP (August 2016)
#[derive(PartialEq, Debug)]
pub struct OPENPGPKEY {

    /// The PGP key, as unencoded bytes.
    pub key: Vec<u8>,
}

impl Wire for OPENPGPKEY {
    const NAME: &'static str = "OPENPGPKEY";
    const RR_TYPE: u16 = 61;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length == 0 {
            let mandated_length = MandatedLength::AtLeast(1);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let mut key = vec![0_u8; usize::from(stated_length)];
        c.read_exact(&mut key)?;
        trace!("Parsed key -> {:#x?}", key);

        Ok(Self { key })
    }
}

impl OPENPGPKEY {

    /// The base64-encoded PGP key.
    pub fn base64_key(&self) -> String {
        base64::encode(&self.key)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x12, 0x34, 0x56, 0x78,  // key
        ];

        assert_eq!(OPENPGPKEY::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   OPENPGPKEY {
                       key: vec![ 0x12, 0x34, 0x56, 0x78 ],
                   });
    }

    #[test]
    fn one_byte_of_uri() {
        let buf = &[
            0x2b,  // one byte of key
        ];

        assert_eq!(OPENPGPKEY::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   OPENPGPKEY {
                       key: vec![ 0x2b ],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(OPENPGPKEY::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::AtLeast(1) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x12, 0x34,  // the beginning of a key
        ];

        assert_eq!(OPENPGPKEY::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
