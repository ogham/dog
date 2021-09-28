//! Reading strings from the DNS wire protocol.

use std::convert::TryFrom;
use std::fmt;
use std::io::{self, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};
use log::*;

use crate::wire::*;


/// Domain names in the DNS protocol are encoded as **Labels**, which are
/// segments of ASCII characters prefixed by their length. When written out,
/// each segment is followed by a dot.
///
/// The maximum length of a segment is 255 characters.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Labels {
    segments: Vec<(u8, String)>,
}

#[cfg(feature = "with_idna")]
fn label_to_ascii(label: &str) -> Result<String, unic_idna::Errors> {
    let flags = unic_idna::Flags{use_std3_ascii_rules: false, transitional_processing: false, verify_dns_length: true};
    unic_idna::to_ascii(label, flags)
}

#[cfg(not(feature = "with_idna"))]
fn label_to_ascii(label: &str) -> Result<String, ()> {
    Ok(label.to_owned())
}

impl Labels {

    /// Creates a new empty set of labels, which represent the root of the DNS
    /// as a domain with no name.
    pub fn root() -> Self {
        Self { segments: Vec::new() }
    }

    /// Encodes the given input string as labels. If any segment is too long,
    /// returns that segment as an error.
    pub fn encode(input: &str) -> Result<Self, &str> {
        let mut segments = Vec::new();

        for label in input.split('.') {
            if label.is_empty() {
                continue;
            }

            let label_idn = label_to_ascii(label)
                    .map_err(|e| {
                        warn!("Could not encode label {:?}: {:?}", label, e);
                        label
                    })?;

            match u8::try_from(label_idn.len()) {
                Ok(length) => {
                    segments.push((length, label_idn));
                }
                Err(e) => {
                    warn!("Could not encode label {:?}: {}", label, e);
                    return Err(label);
                }
            }
        }

        Ok(Self { segments })
    }

    /// Returns the number of segments.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns a new set of labels concatenating two names.
    pub fn extend(&self, other: &Self) -> Self {
        let mut segments = self.segments.clone();
        segments.extend_from_slice(&other.segments);
        Self { segments }
    }
}

impl fmt::Display for Labels {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (_, segment) in &self.segments {
            write!(f, "{}.", segment)?;
        }

        Ok(())
    }
}

/// An extension for `Cursor` that enables reading compressed domain names
/// from DNS packets.
pub(crate) trait ReadLabels {

    /// Read and expand a compressed domain name.
    fn read_labels(&mut self) -> Result<(Labels, u16), WireError>;
}

impl ReadLabels for Cursor<&[u8]> {
    fn read_labels(&mut self) -> Result<(Labels, u16), WireError> {
        let mut labels = Labels { segments: Vec::new() };
        let bytes_read = read_string_recursive(&mut labels, self, &mut Vec::new())?;
        Ok((labels, bytes_read))
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
    fn write_labels(&mut self, input: &Labels) -> io::Result<()>;
}

impl<W: Write> WriteLabels for W {
    fn write_labels(&mut self, input: &Labels) -> io::Result<()> {
        for (length, label) in &input.segments {
            self.write_u8(*length)?;

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
#[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
fn read_string_recursive(labels: &mut Labels, c: &mut Cursor<&[u8]>, recursions: &mut Vec<u16>) -> Result<u16, WireError> {
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
                return Err(WireError::TooMuchRecursion(recursions.clone().into_boxed_slice()));
            }

            recursions.push(offset);

            if recursions.len() >= RECURSION_LIMIT {
                warn!("Hit recursion limit ({}) decoding string", RECURSION_LIMIT);
                return Err(WireError::TooMuchRecursion(recursions.clone().into_boxed_slice()));
            }

            trace!("Backtracking to offset {}", offset);
            let new_pos = c.position();
            c.set_position(u64::from(offset));

            read_string_recursive(labels, c, recursions)?;

            trace!("Coming back to {}", new_pos);
            c.set_position(new_pos);
            break;
        }

        // Otherwise, treat the byte as the length of a label, and read that
        // many characters.
        else {
            let mut name_buf = Vec::new();

            for _ in 0 .. byte {
                let c = c.read_u8()?;
                bytes_read += 1;
                name_buf.push(c);
            }

            let string = String::from_utf8_lossy(&*name_buf).to_string();
            labels.segments.push((byte, string));
        }
    }

    Ok(bytes_read)
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

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
                   Ok((Labels::root(), 1)));
    }

    #[test]
    fn one_label() {
        let buf: &[u8] = &[
            0x03,  // label of length 3
            b'o', b'n', b'e',  // label
            0x00,  // end reading
        ];

        assert_eq!(Cursor::new(buf).read_labels(),
                   Ok((Labels::encode("one.").unwrap(), 5)));
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
                   Ok((Labels::encode("one.two.").unwrap(), 9)));
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
                   Ok((Labels::encode("one.two.").unwrap(), 6)));
    }

    #[test]
    fn extremely_long_label() {
        let mut buf: Vec<u8> = vec![
            0xbf,  // label of length 191
        ];

        buf.extend(vec![0x65; 191]);  // the rest of the label
        buf.push(0x00);  // end reading

        assert_eq!(Cursor::new(&*buf).read_labels().unwrap().1, 193);
    }

    #[test]
    fn immediate_recursion() {
        let buf: &[u8] = &[
            0xc0, 0x00,  // skip to position 0
        ];

        assert_eq!(Cursor::new(buf).read_labels(),
                   Err(WireError::TooMuchRecursion(Box::new([ 0 ]))));
    }

    #[test]
    fn mutual_recursion() {
        let buf: &[u8] = &[
            0xc0, 0x02,  // skip to position 2
            0xc0, 0x00,  // skip to position 0
        ];

        let mut cursor = Cursor::new(buf);

        assert_eq!(cursor.read_labels(),
                   Err(WireError::TooMuchRecursion(Box::new([ 2, 0 ]))));
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
                   Err(WireError::TooMuchRecursion(Box::new([ 2, 4, 6, 8, 10, 12, 14, 16 ]))));
    }
}
