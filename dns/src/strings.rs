//! Reading strings from the DNS wire protocol.

use std::fmt;
use std::io::{self, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};
use log::*;

use crate::wire::*;


/// Domain names in the DNS protocol are encoded as **Labels**, which are
/// segments of bytes prefixed by their length. When written out, each
/// segment is followed by a dot.
///
/// A label read from a packet can hold any bytes at all, so they are kept
/// exactly as received, and only escaped when the name is displayed.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Labels {
    segments: Vec<Vec<u8>>,
}

/// The longest a label can be (RFC 1035 §2.3.4).
const MAX_LABEL: usize = 63;

/// The longest a whole name can be on the wire, counting the length byte of
/// every label and the zero that ends the name (RFC 1035 §2.3.4).
const MAX_NAME: usize = 255;

/// Why a name cannot be encoded as labels.
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct InvalidName(String);

impl fmt::Display for InvalidName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Converts one label to its ASCII form using UTS 46 processing, as dog has
/// always applied it: characters outside the STD3 rules are allowed (so
/// service labels such as `_dmarc` work), and a hyphen may not start or end
/// a label. The label’s length is checked separately.
#[cfg(feature = "with_idna")]
fn label_to_ascii(label: &str) -> Result<String, idna::Errors> {
    use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};

    Uts46::new()
        .to_ascii(label.as_bytes(), AsciiDenyList::EMPTY, Hyphens::CheckFirstLast, DnsLength::Ignore)
        .map(std::borrow::Cow::into_owned)
}

/// Without IDNA support, labels are used just as they are given.
#[cfg(not(feature = "with_idna"))]
#[allow(clippy::unnecessary_wraps)]  // it has the same signature as the IDNA version
fn label_to_ascii(label: &str) -> Result<String, ()> {
    Ok(label.to_owned())
}

/// Encodes one label of a name typed by the user.
fn encode_label(label: &str) -> Result<Vec<u8>, InvalidName> {
    if label.is_empty() {
        return Err(InvalidName("it has an empty label".into()));
    }

    if label.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(InvalidName(format!("its label {label:?} contains a space or a control character")));
    }

    let ascii = label_to_ascii(label).map_err(|e| {
        warn!("Could not encode label {label:?}: {e:?}");
        InvalidName(format!("its label {label:?} is not a valid internationalised name"))
    })?;

    if ascii.len() > MAX_LABEL {
        return Err(InvalidName(format!("its label {label:?} is longer than {MAX_LABEL} bytes")));
    }

    Ok(ascii.into_bytes())
}

impl Labels {

    /// Creates a new empty set of labels, which represent the root of the DNS
    /// as a domain with no name.
    pub fn root() -> Self {
        Self { segments: Vec::new() }
    }

    /// Encodes a name typed by the user as labels. A final dot is allowed,
    /// and a lone dot is the root.
    ///
    /// # Errors
    ///
    /// Returns the reason the name is invalid if it is empty, has an empty
    /// label, has a label containing a space or a control character, has a
    /// label that is not a valid internationalised name or is longer than 63
    /// bytes, or is longer than 255 bytes in all.
    pub fn encode(input: &str) -> Result<Self, InvalidName> {
        if input == "." {
            return Ok(Self::root());
        }

        if input.is_empty() {
            return Err(InvalidName("it is empty".into()));
        }

        let without_root = input.strip_suffix('.').unwrap_or(input);
        let segments = without_root.split('.').map(encode_label).collect::<Result<Vec<_>, _>>()?;
        let labels = Self { segments };

        if labels.wire_length() > MAX_NAME {
            return Err(InvalidName(format!("it is longer than {MAX_NAME} bytes")));
        }

        Ok(labels)
    }

    /// How many bytes the name takes up in a packet, uncompressed.
    fn wire_length(&self) -> usize {
        self.segments.iter().map(|segment| segment.len() + 1).sum::<usize>() + 1
    }

    /// Returns the number of segments.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Returns a new set of labels concatenating two names.
    #[must_use]
    pub fn extend(&self, other: &Self) -> Self {
        let mut segments = self.segments.clone();
        segments.extend_from_slice(&other.segments);
        Self { segments }
    }

    /// Whether two names are the same name, as DNS compares them: without
    /// regard to the case of ASCII letters (RFC 4343).
    pub fn eq_ignore_ascii_case(&self, other: &Self) -> bool {
        self.segments.len() == other.segments.len()
            && self.segments.iter().zip(&other.segments).all(|(a, b)| a.eq_ignore_ascii_case(b))
    }
}

impl fmt::Display for Labels {

    /// Writes the name in the master file format of RFC 1035 §5.1, as dig
    /// does: printable ASCII as itself, a dot, backslash, or quote inside a
    /// label escaped with a backslash, and every other byte as a backslash
    /// and its three-digit decimal value. Names come from servers, so this
    /// keeps a hostile one from sending terminal escape sequences or line
    /// breaks through dog to the user’s terminal.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The root is a name with no segments, and its representation is a
        // lone dot — not the empty string. Without this the loop below writes
        // nothing, and a record whose value IS the root becomes indistinguishable
        // from a record with no value at all.
        //
        // That distinction carries meaning. "example.com. MX 0 ." is RFC 7505
        // null MX: an explicit statement that the domain accepts no mail, and
        // therefore cannot be the source of any. Rendered as "", it reads as
        // "no exchange value available". RFC 3403 NAPTR uses a root replacement
        // the same way, to mean terminal.
        if self.segments.is_empty() {
            return write!(f, ".");
        }

        for segment in &self.segments {
            for byte in segment.iter().copied() {
                write_name_byte(f, byte)?;
            }
            f.write_str(".")?;
        }

        Ok(())
    }
}

/// Writes one byte of a label for `Labels`’ `Display`.
fn write_name_byte(f: &mut fmt::Formatter<'_>, byte: u8) -> fmt::Result {
    match byte {
        b'.' | b'\\' | b'"'  => write!(f, "\\{}", char::from(byte)),
        0x21 ..= 0x7E        => write!(f, "{}", char::from(byte)),
        _                    => write!(f, "\\{byte:03}"),
    }
}


#[cfg(test)]
mod display_test {
    use super::*;

    /// The root is a lone dot, not the empty string.
    ///
    /// "example.com. MX 0 ." is RFC 7505 null MX — an explicit statement that
    /// the domain accepts no mail and so cannot be the source of any. Rendered
    /// as "" it became indistinguishable from a missing value, and a consumer
    /// asking whether a domain can send mail lost an unambiguous answer.
    #[test]
    fn root_renders_as_dot() {
        assert_eq!(Labels::root().to_string(), ".");
    }

    #[test]
    fn encoded_dot_is_the_root() {
        assert_eq!(Labels::encode(".").unwrap().to_string(), ".");
    }

    /// Ordinary names are unaffected: every segment still trails a dot.
    #[test]
    fn ordinary_names_are_unchanged() {
        assert_eq!(Labels::encode("example.com").unwrap().to_string(), "example.com.");
        assert_eq!(Labels::encode("a.b.c").unwrap().to_string(), "a.b.c.");
        assert_eq!(Labels::encode("localhost").unwrap().to_string(), "localhost.");
    }

    fn read(bytes: &[u8]) -> Labels {
        Cursor::new(bytes).read_labels().unwrap().0
    }

    /// Names from a server can hold anything; what would control a terminal
    /// or break a line is written as a number instead, as dig writes it.
    #[test]
    fn unprintable_bytes_are_escaped() {
        assert_eq!(read(b"\x0a\x1b]0;pwned\x07\x00").to_string(), r"\027]0;pwned\007.");
        assert_eq!(read(b"\x0bline\nforged\x00").to_string(), r"line\010forged.");
        assert_eq!(read(b"\x03a b\x01\x00\x00").to_string(), r"a\032b.\000.");
        assert_eq!(read(b"\x02\xc3\xa9\x00").to_string(), r"\195\169.");
        assert_eq!(read(b"\x01\x7f\x00").to_string(), r"\127.");
    }

    /// A dot inside a label is not the end of the label, and a backslash or
    /// a quote would otherwise be read as the start of an escape or the end
    /// of a quoted name.
    #[test]
    fn special_characters_are_escaped() {
        assert_eq!(read(b"\x03a.b\x03com\x00").to_string(), r"a\.b.com.");
        assert_eq!(read(b"\x03a\\b\x00").to_string(), r"a\\b.");
        assert_eq!(read(b"\x03a\"b\x00").to_string(), r#"a\"b."#);
    }

    /// Every printable character other than those stays as it is.
    #[test]
    fn printable_characters_are_kept() {
        assert_eq!(read(b"\x0a_a-Z*~@%$!\x00").to_string(), "_a-Z*~@%$!.");
    }
}


#[cfg(test)]
mod encode_test {
    use super::*;

    fn invalid(input: &str) -> String {
        Labels::encode(input).unwrap_err().to_string()
    }

    /// dig refuses these names rather than guessing what was meant, and so
    /// does dog; before, it quietly dropped the empty labels and sent a
    /// different name, or the root.
    #[test]
    fn empty_names_and_labels() {
        assert_eq!(invalid(""), "it is empty");
        for input in [ "a..b", ".example.com", "example.com..", "..", "a.b.c...d" ] {
            assert_eq!(invalid(input), "it has an empty label", "{input:?}");
        }
    }

    #[test]
    fn a_final_dot_is_allowed() {
        assert_eq!(Labels::encode("example.com.").unwrap(), Labels::encode("example.com").unwrap());
    }

    #[test]
    fn spaces_and_control_characters() {
        assert_eq!(invalid(" example.com"), r#"its label " example" contains a space or a control character"#);
        assert_eq!(invalid("a b.example"), r#"its label "a b" contains a space or a control character"#);
        assert_eq!(invalid("\x1b[31mred.example"), r#"its label "\u{1b}[31mred" contains a space or a control character"#);
        assert_eq!(invalid("line\nbreak.example"), r#"its label "line\nbreak" contains a space or a control character"#);
        assert_eq!(invalid("tab\t.example"), r#"its label "tab\t" contains a space or a control character"#);
        assert_eq!(invalid("del\x7f.example"), r#"its label "del\u{7f}" contains a space or a control character"#);
    }

    #[test]
    fn label_lengths() {
        let longest = "a".repeat(63);
        assert!(Labels::encode(&format!("{longest}.example")).is_ok());
        assert_eq!(invalid(&format!("{longest}a.example")), format!("its label \"{longest}a\" is longer than 63 bytes"));
    }

    /// 255 bytes on the wire is the limit: four labels of 63 bytes, each with
    /// its length byte, plus the final zero, is 257 bytes; one byte less in
    /// each of two labels makes exactly 255.
    #[test]
    fn name_lengths() {
        let label = "a".repeat(63);
        let shorter = "a".repeat(62);
        assert!(Labels::encode(&format!("{label}.{label}.{shorter}.{shorter}")).is_ok());
        assert_eq!(invalid(&format!("{label}.{label}.{label}.{shorter}")), "it is longer than 255 bytes");
        assert_eq!(invalid(&[ "a"; 128 ].join(".")), "it is longer than 255 bytes");
    }

    #[test]
    fn written_labels_fit_their_length_byte() {
        let mut bytes = Vec::new();
        bytes.write_labels(&Labels::encode("dns.lookup.dog").unwrap()).unwrap();
        assert_eq!(bytes, b"\x03dns\x06lookup\x03dog\x00");

        let too_long = Labels { segments: vec![ vec![ b'a'; 256 ] ] };
        assert_eq!(Vec::new().write_labels(&too_long).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn names_compare_without_regard_to_case() {
        let lower = Labels::encode("dns.lookup.dog").unwrap();
        assert!(lower.eq_ignore_ascii_case(&Cursor::new(&b"\x03DNS\x06Lookup\x03dog\x00"[..]).read_labels().unwrap().0));
        assert!(!lower.eq_ignore_ascii_case(&Labels::encode("dns.lookup").unwrap()));
        assert!(!lower.eq_ignore_ascii_case(&Labels::encode("dns.lookup.cat").unwrap()));
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
        for label in &input.segments {
            let length = u8::try_from(label.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "a label is too long for its length byte"))?;
            self.write_u8(length)?;
            self.write_all(label)?;
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
                warn!("Hit previous offset ({offset}) decoding string");
                return Err(WireError::TooMuchRecursion(recursions.clone().into_boxed_slice()));
            }

            recursions.push(offset);

            if recursions.len() >= RECURSION_LIMIT {
                warn!("Hit recursion limit ({RECURSION_LIMIT}) decoding string");
                return Err(WireError::TooMuchRecursion(recursions.clone().into_boxed_slice()));
            }

            trace!("Backtracking to offset {offset}");
            let new_pos = c.position();
            c.set_position(u64::from(offset));

            read_string_recursive(labels, c, recursions)?;

            trace!("Coming back to {new_pos}");
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

            labels.segments.push(name_buf);
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
