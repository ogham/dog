use crate::wire::*;

use log::*;


/// A **TXT** record, which holds arbitrary descriptive text.
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
pub struct TXT {

    /// The message contained in the record.
    pub message: String,
}

impl Wire for TXT {
    const NAME: &'static str = "TXT";
    const RR_TYPE: u16 = 16;

    #[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let mut buf = Vec::new();
        let mut total_len = 0_usize;

        loop {
            let next_len = c.read_u8()?;
            total_len += next_len as usize + 1;

            for _ in 0 .. next_len {
                buf.push(c.read_u8()?);
            }

            if next_len < 255 {
                break;
            }
            else {
                debug!("Got length 255 so looping");
            }
        }

        if total_len == len as usize {
            debug!("Length matches expected");
        }
        else {
            warn!("Expected length {} but read {} bytes", len, buf.len());
        }

        let message = String::from_utf8_lossy(&buf).to_string();
        Ok(TXT { message })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x06, 0x74, 0x78, 0x74, 0x20, 0x6d, 0x65,  // message
        ];

        assert_eq!(TXT::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   TXT {
                       message: String::from("txt me"),
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(TXT::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}
