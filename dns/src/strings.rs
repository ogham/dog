//! Reading strings from the DNS wire protocol.

use std::io::{self, Write};

use log::debug;
use byteorder::{ReadBytesExt, WriteBytesExt};

use crate::wire::*;


/// An extension for `Cursor` that enables reading compressed domain names
/// from DNS packets.
pub(crate) trait ReadLabels {

    /// Read and expand a compressed domain name.
    fn read_labels(&mut self) -> Result<String, WireError>;
}

impl ReadLabels for Cursor<&[u8]> {
    fn read_labels(&mut self) -> Result<String, WireError> {
        let mut name_buf = Vec::new();
        read_string_recursive(&mut name_buf, self, &mut Vec::new())?;
        Ok(String::from_utf8_lossy(&*name_buf).to_string())
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

#[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
fn read_string_recursive(name_buf: &mut Vec<u8>, c: &mut Cursor<&[u8]>, recursions: &mut Vec<u16>) -> Result<(), WireError> {
    loop {
        let byte = c.read_u8()?;

        if byte == 0 {
            break;
        }

        else if byte >= 0b_1100_0000 {
            if recursions.len() >= RECURSION_LIMIT {
                return Err(WireError::TooMuchRecursion(recursions.clone()));
            }

            let name_one = byte - 0b1100_0000;
            let name_two = c.read_u8()?;
            let offset = u16::from_be_bytes([name_one, name_two]);

            debug!("Backtracking to offset {}", offset);
            let new_pos = c.position();
            c.set_position(u64::from(offset));
            recursions.push(offset);

            read_string_recursive(name_buf, c, recursions)?;

            debug!("Coming back to {}", new_pos);
            c.set_position(new_pos);
            recursions.pop();
            break;
        }

        // Otherwise, treat the byte as the length of a label, and read that
        // many characters.
        else {
            for _ in 0 .. byte {
                let c = c.read_u8()?;
                name_buf.push(c);
            }

            name_buf.push(b'.');
        }
    }

    Ok(())
}
