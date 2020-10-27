//! Reading strings from the DNS wire protocol.

use std::io::{self, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};
use log::*;

use crate::wire::*;


/// An extension for `Cursor` that enables reading compressed domain names
/// from DNS packets.
pub(crate) trait ReadLabels {

    /// Read and expand a compressed domain name.
    fn read_labels(&mut self) -> Result<(String, u16), WireError>;
}

impl ReadLabels for Cursor<&[u8]> {
    fn read_labels(&mut self) -> Result<(String, u16), WireError> {
        let mut name_buf = Vec::new();
        let bytes_read = read_string_recursive(&mut name_buf, self, &mut Vec::new())?;
        let string = String::from_utf8_lossy(&*name_buf).to_string();
        Ok((string, bytes_read))
    }
}


/// An extension for `Write` that enables writing domain names.
pub(crate) trait WriteLabels {

    /// Write a domain name.
    ///
    /// The names being queried are written with one byte slice per
    /// domain segment, preceded by each segment’s length, with the
    /// whole thing ending with a segment of zero length.
    ///
    /// So “dns.lookup.dog” would be encoded as:
    /// “3, dns, 6, lookup, 3, dog, 0”.
    fn write_labels(&mut self, input: &str) -> io::Result<()>;
}

impl<W: Write> WriteLabels for W {
    fn write_labels(&mut self, input: &str) -> io::Result<()> {
        for label in input.split('.') {
            self.write_u8(label.len() as u8)?;

            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;  // terminate the string
        Ok(())
    }
}


const RECURSION_LIMIT: usize = 8;

/// Reads bytes from the given cursor into the given buffer, using the list of
/// recursions to track backtracking positions. Returns the count of bytes
/// that had to be read to produce the string, including the bytes to signify
/// backtracking, but not including the bytes read _during_ backtracking.
#[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
fn read_string_recursive(name_buf: &mut Vec<u8>, c: &mut Cursor<&[u8]>, recursions: &mut Vec<u16>) -> Result<u16, WireError> {
    let mut bytes_read = 0;

    loop {
        let byte = c.read_u8()?;
        bytes_read += 1;

        if byte == 0 {
            break;
        }

        else if byte >= 0b_1100_0000 {
            let name_one = byte - 0b1100_0000;
            let name_two = c.read_u8()?;
            bytes_read += 1;
            let offset = u16::from_be_bytes([name_one, name_two]);

            if recursions.contains(&offset) {
                warn!("Hit previous offset ({}) decoding string", offset);
                return Err(WireError::TooMuchRecursion(recursions.clone()));
            }

            recursions.push(offset);

            if recursions.len() >= RECURSION_LIMIT {
                warn!("Hit recursion limit ({}) decoding string", RECURSION_LIMIT);
                return Err(WireError::TooMuchRecursion(recursions.clone()));
            }

            trace!("Backtracking to offset {}", offset);
            let new_pos = c.position();
            c.set_position(u64::from(offset));

            read_string_recursive(name_buf, c, recursions)?;

            trace!("Coming back to {}", new_pos);
            c.set_position(new_pos);
            break;
        }

        // Otherwise, treat the byte as the length of a label, and read that
        // many characters.
        else {
            for _ in 0 .. byte {
                let c = c.read_u8()?;
                bytes_read += 1;
                name_buf.push(c);
            }

            name_buf.push(b'.');
        }
    }

    Ok(bytes_read)
}


#[cfg(test)]
mod test {
    use super::*;

    // The buffers used in these tests contain nothing but the labels we’re
    // decoding. In DNS packets found in the wild, the cursor will be able to
    // reach all the bytes of the packet, so the Answer section can reference
    // strings in the Query section.

    #[test]
    fn nothing() {
        let buf: &[u8] = &[
            0x00,  // end reading
        ];

        assert_eq!(Cursor::new(buf).read_labels(),
                   Ok(("".into(), 1)));
    }

    #[test]
    fn one_label() {
        let buf: &[u8] = &[
            0x03,  // label of length 3
            b'o', b'n', b'e',  // label
            0x00,  // end reading
        ];

        assert_eq!(Cursor::new(buf).read_labels(),
                   Ok(("one.".into(), 5)));
    }

    #[test]
    fn two_labels() {
        let buf: &[u8] = &[
            0x03,  // label of length 3
            b'o', b'n', b'e',  // label
            0x03,  // label of length 3
            b't', b'w', b'o',  // label
            0x00,  // end reading
        ];

        assert_eq!(Cursor::new(buf).read_labels(),
                   Ok(("one.two.".into(), 9)));
    }

    #[test]
    fn label_followed_by_backtrack() {
        let buf: &[u8] = &[
            0x03,  // label of length 3
            b'o', b'n', b'e',  // label
            0xc0, 0x06,  // skip to position 6 (the next byte)

            0x03,  // label of length 3
            b't', b'w', b'o',  // label
            0x00,  // end reading
        ];

        assert_eq!(Cursor::new(buf).read_labels(),
                   Ok(("one.two.".into(), 6)));
    }

    #[test]
    fn extremely_long_label() {
        let mut buf: Vec<u8> = vec![
            0xbf,  // label of length 191
        ];

        buf.extend(&[0x65; 191]);  // the rest of the label
        buf.push(0x00);  // end reading

        assert_eq!(Cursor::new(&*buf).read_labels().unwrap().1, 193);
    }

    #[test]
    fn immediate_recursion() {
        let buf: &[u8] = &[
            0xc0, 0x00,  // skip to position 0
        ];

        assert_eq!(Cursor::new(buf).read_labels(),
                   Err(WireError::TooMuchRecursion(vec![ 0 ])));
    }

    #[test]
    fn mutual_recursion() {
        let buf: &[u8] = &[
            0xc0, 0x02,  // skip to position 2
            0xc0, 0x00,  // skip to position 0
        ];

        let mut cursor = Cursor::new(buf);

        assert_eq!(cursor.read_labels(),
                   Err(WireError::TooMuchRecursion(vec![ 2, 0 ])));
    }

    #[test]
    fn too_much_recursion() {
        let buf: &[u8] = &[
            0xc0, 0x02,  // skip to position 2
            0xc0, 0x04,  // skip to position 4
            0xc0, 0x06,  // skip to position 6
            0xc0, 0x08,  // skip to position 8
            0xc0, 0x0A,  // skip to position 10
            0xc0, 0x0C,  // skip to position 12
            0xc0, 0x0E,  // skip to position 14
            0xc0, 0x10,  // skip to position 16
            0x00,        // no label
        ];

        let mut cursor = Cursor::new(buf);

        assert_eq!(cursor.read_labels(),
                   Err(WireError::TooMuchRecursion(vec![ 2, 4, 6, 8, 10, 12, 14, 16 ])));
    }
}
