#![allow(dead_code)]

use core::fmt::{self, Display};
use std::borrow::Cow;
use std::iter::FromIterator;

/// Parameters to a SVCB/HTTPS record can be multi-valued.
/// This is a fancy comma-separated list, where escaped commas \, and \044 do not separate
/// values.
///
/// # References:
///
/// [Draft RFC](https://tools.ietf.org/id/draft-ietf-dnsop-svcb-https-02.html#name-the-svcb-record-type), section A.1
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct ValueList {
    /// The parsed values
    pub values: Vec<Vec<u8>>,
}

impl<A: Into<Vec<u8>>> FromIterator<A> for ValueList {
    fn from_iter<I: IntoIterator<Item = A>>(iter: I) -> Self {
        let values = iter.into_iter().map(|x| x.into()).collect();
        Self { values }
    }
}
impl<A: Into<Vec<u8>>> From<Vec<A>> for ValueList {
    fn from(vec: Vec<A>) -> Self {
        let values = vec.into_iter().map(|x| x.into()).collect();
        Self { values }
    }
}

/// Nice
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct SingleValue {
    /// The value
    pub value: Vec<u8>,
}

fn wrap_iresult_complete<T>(result: IResult<&[u8], T>) -> Result<T, DecodingError> {
    result
        .finish()
        .map_err(|e| DecodingError::new(e.input))
        .and_then(|(remain, t)| {
            if remain.is_empty() {
                Ok(t)
            } else {
                Err(DecodingError::new(remain))
            }
        })
}

/// An error that occurred while decoding a char-string or value-list
#[derive(Debug, Clone, PartialEq)]
pub struct DecodingError {
    input: Vec<u8>,
}

impl DecodingError {
    fn new(input: &[u8]) -> Self {
        Self {
            input: input.to_vec(),
        }
    }
}

impl std::error::Error for DecodingError {}
impl fmt::Display for DecodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error decoding, occurred at: {:x?}", self.input)
    }
}

impl ValueList {
    /// New
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Parses a comma separated list with escaping as defined in Appendix A.1. This variant has
    /// unlimited size for each value.
    pub fn parse(input: &[u8]) -> Result<Self, DecodingError> {
        let cow = wrap_iresult_complete(char_string_decoding::parse(input.as_ref()))?;
        let val = wrap_iresult_complete(value_list_decoding::parse(&cow))?;
        Ok(ValueList { values: val })
    }
}

impl SingleValue {
    /// Parse with char-string decoding
    pub fn parse(input: &[u8]) -> Result<Self, DecodingError> {
        let value = wrap_iresult_complete(char_string_decoding::parse(&input))?;
        Ok(Self {
            value: value.into_owned(),
        })
    }
}

#[test]
fn rfc_example() {
    let one = br#""part1,part2,part3\\,part4\\\\""#;
    let two = br#"part1\,\p\a\r\t2\044part3\092,part4\092\\"#;
    let expected_string = br"part1,part2,part3\,part4\\".to_vec();
    let expected_values = vec![
        br"part1".to_vec(),
        br"part2".to_vec(),
        br"part3,part4\".to_vec(),
    ];
    assert_eq!(SingleValue::parse(one).unwrap().value, expected_string);
    assert_eq!(SingleValue::parse(two).unwrap().value, expected_string);
    assert_eq!(ValueList::parse(one).unwrap().values, expected_values);
    assert_eq!(ValueList::parse(two).unwrap().values, expected_values);
}

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::combinator::recognize;
use nom::error::ParseError;
use nom::sequence::preceded;
use nom::IResult;
use nom::{Finish, Parser};

#[cfg(test)]
fn strings(x: IResult<&[u8], Vec<u8>>) -> IResult<&str, String> {
    x.map(|(remain, output)| {
        (
            std::str::from_utf8(remain).unwrap(),
            String::from_utf8(output).unwrap(),
        )
    })
    .map_err(|x| {
        x.map(|y| {
            <_ as ParseError<&str>>::from_error_kind(std::str::from_utf8(y.input).unwrap(), y.code)
        })
    })
}

/// Tools for encoding and decoding value-list and char-string
pub mod encoding {
    use super::*;

    pub use super::DecodingError;
    pub use super::SingleValue;
    pub use super::ValueList;

    /// Iterates a parser over an input. Expects it does not fail or return Incomplete. It stops
    /// parsing when the parser returns nom::Err::Error (which should occur at Eof).
    fn iter_parser<I: Copy, O, E>(
        input: I,
        mut parser: impl Parser<I, O, E> + Clone,
    ) -> impl Iterator<Item = O> + Clone {
        let mut remain = input;
        core::iter::from_fn(move || match parser.parse(remain) {
            Ok((rest, chunk)) => {
                remain = rest;
                Some(chunk)
            }
            Err(nom::Err::Error(..)) => None,
            Err(nom::Err::Failure(..)) => panic!("iter_parser encountered nom::Err::Failure"),
            Err(nom::Err::Incomplete(..)) => panic!("iter_parser encountered nom::Err::Incomplete"),
        })
    }

    /// Pops a single byte off the front of the input
    fn single_byte(input: &[u8]) -> IResult<&[u8], u8> {
        let (byte, remain) = input.split_first().ok_or_else(|| {
            nom::Err::Error(ParseError::from_error_kind(
                input,
                nom::error::ErrorKind::Char,
            ))
        })?;
        Ok((remain, *byte))
    }

    #[derive(Debug, Clone)]
    enum EncodingChunk<'a> {
        Slice(&'a [u8]),
        Escape(&'a str),
        Byte(u8),
    }

    mod char_string {
        use super::*;
        fn chunk(remain: &[u8]) -> IResult<&[u8], EncodingChunk<'_>> {
            super::super::char_string_decoding::non_special
                .map(EncodingChunk::Slice)
                // special treatment for these few, not matched by is_non_special
                .or(tag(br"\").map(|_| EncodingChunk::Escape(r"\\")))
                .or(tag(b";").map(|_| EncodingChunk::Escape(r"\;")))
                .or(tag(b"\"").map(|_| EncodingChunk::Escape("\\\"")))
                .or(tag(b"(").map(|_| EncodingChunk::Escape("\\(")))
                .or(tag(b")").map(|_| EncodingChunk::Escape("\\)")))
                // or any other byte
                .or(single_byte.map(EncodingChunk::Byte))
                .parse(remain)
        }

        pub(super) fn emit_chunks(input: &[u8]) -> impl Iterator<Item = EncodingChunk<'_>> + Clone {
            iter_parser(input, chunk)
        }
    }

    mod value_list {
        use super::*;
        fn chunk(remain: &[u8]) -> IResult<&[u8], EncodingChunk<'_>> {
            super::super::value_list_decoding::item_allowed
                // .or(tag(br"\\"))
                // .or(tag(br"\,"))
                .map(EncodingChunk::Slice)
                // .or(single_byte.map(EncodingChunk::Byte))
                .or(tag(br"\").map(|_| EncodingChunk::Escape(r"\\")))
                .or(tag(br",").map(|_| EncodingChunk::Escape(r"\,")))
                .parse(remain)
        }

        pub(super) fn emit_chunks(input: &[u8]) -> impl Iterator<Item = EncodingChunk<'_>> + Clone {
            iter_parser(input, chunk)
        }
    }

    fn format_iter<'a, I>(iter: I) -> impl fmt::Display + 'a
    where
        I: Iterator<Item = EncodingChunk<'a>> + Clone + 'a,
    {
        display_utils::join_format(iter, "", |chunk, f| match chunk {
            EncodingChunk::Slice(slice) => {
                // Technically we know this is printable ASCII. is that utf8?
                let string = std::str::from_utf8(slice).map_err(|e| {
                    log::error!("error escaping string: {}", e);
                    fmt::Error
                })?;
                f.write_str(string)?;
                Ok(())
            }
            EncodingChunk::Escape(str) => str.fmt(f),
            EncodingChunk::Byte(byte) => {
                write!(f, "\\{:03}", byte)
            }
        })
    }

    /// Display implementation that escapes a string
    pub struct EscapeCharString<A: AsRef<[u8]>>(pub A);

    impl<A: AsRef<[u8]>> Display for EscapeCharString<A> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let string = self.0.as_ref();
            let chunks = char_string::emit_chunks(string);
            let iter = format_iter(chunks);
            if string.contains(&b' ') || string.contains(&b'\t') || string.contains(&b'"') {
                write!(f, "\"{}\"", iter)
            } else {
                iter.fmt(f)
            }
        }
    }

    #[test]
    fn test_escape_char_string() {
        assert_eq!(EscapeCharString(br"\").to_string(), r"\\");
    }

    /// Takes an iterator of `&[u8]` and implements Display, writing in value-list (escaped
    /// comma-separated) encoding for presentation of lists of strings.
    pub struct EscapeValueList<'a, I: IntoIterator<Item = &'a [u8]> + Clone>(pub I);

    impl<'a, I> fmt::Display for EscapeValueList<'a, I>
    where
        I: IntoIterator<Item = &'a [u8]> + Clone,
        I::IntoIter: Clone,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let values = self.0.clone().into_iter();
            let chunk_iter = values.map(|value| {
                let chunks = value_list::emit_chunks(value);
                let char_escaped_chunks = chunks
                    .map(|encoding_chunk| match encoding_chunk {
                        EncodingChunk::Slice(slice) => slice,
                        EncodingChunk::Escape(str) => str.as_bytes(),
                        EncodingChunk::Byte(_byte) => unreachable!(
                            "encountered EncodingChunk::Byte, not used in value_list::emit_chunks"
                        ),
                    })
                    .map(EscapeCharString);
                display_utils::concat(char_escaped_chunks)
            });
            display_utils::join(chunk_iter, ",").fmt(f)
        }
    }

    impl fmt::Display for ValueList {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            EscapeValueList(self.values.iter().map(|val| val.as_slice())).fmt(f)
        }
    }

    impl fmt::Display for SingleValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let bytes = self.value.as_slice();
            EscapeCharString(bytes).fmt(f)
        }
    }
}

fn dec_octet(buf: &[u8], zero_one_or_two: u8) -> IResult<&[u8], u8> {
    let (hundreds, tens, ones, rest) = match zero_one_or_two {
        hundreds @ (0 | 1) => match buf {
            [tens @ b'0'..=b'9', ones @ b'0'..=b'9', rest @ ..] => {
                (hundreds, tens - b'0', ones - b'0', rest)
            }
            _ => {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    buf,
                    nom::error::ErrorKind::Escaped,
                )))
            }
        },
        hundreds @ 2 => match buf {
            [tens @ b'0'..=b'4', ones @ b'0'..=b'9', rest @ ..]
            | [tens @ b'5', ones @ b'0'..=b'5', rest @ ..] => {
                (hundreds, tens - b'0', ones - b'0', rest)
            }
            _ => {
                return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                    buf,
                    nom::error::ErrorKind::Escaped,
                )))
            }
        },
        _ => {
            return Err(nom::Err::Error(nom::error::Error::from_error_kind(
                buf,
                nom::error::ErrorKind::Escaped,
            )))
        }
    };
    let byte = hundreds * 100 + tens * 10 + ones;
    Ok((rest, byte))
}

#[derive(Debug, Clone)]
pub enum DecodingChunk<'a> {
    Slice(&'a [u8]),
    Byte(u8),
}

fn chunk_1<'a, F, E>(mut inner: F) -> impl Parser<&'a [u8], Cow<'a, [u8]>, E>
where
    F: Parser<&'a [u8], DecodingChunk<'a>, E>,
    E: ParseError<&'a [u8]> + core::fmt::Debug,
{
    move |input| {
        let mut output = Cow::Borrowed(&[][..]);
        let parser = |slice| inner.parse(slice);
        let mut iter = nom::combinator::iterator(input, parser);
        let i = &mut iter;
        let mut success = false;
        for chunk in i {
            success = true;
            match chunk {
                DecodingChunk::Slice(new_slice) => match output {
                    Cow::Borrowed(ref mut slice) => {
                        *slice = &input[..(slice.len() + new_slice.len())]
                    }
                    Cow::Owned(ref mut vec) => vec.extend_from_slice(new_slice),
                },
                // if we have any escapes at all, take ownership of the vec
                DecodingChunk::Byte(byte) => output.to_mut().push(byte),
            }
        }
        let (remain, ()) = iter.finish()?;
        if success {
            Ok((remain, output))
        } else {
            Err(nom::Err::Error(E::from_error_kind(
                input,
                nom::error::ErrorKind::Eof,
            )))
        }
    }
}

mod char_string_decoding {
    use super::*;

    fn char_escape(input: &[u8]) -> IResult<&[u8], u8> {
        let (input, _backslash) = nom::bytes::complete::tag(br"\")(input)?;
        match input {
            // dec-octet, a number 0..=255 as a three digit decimal number
            &[c @ b'0'..=b'2', ref rest @ ..] => {
                let (remain, byte) = dec_octet(rest, c - b'0')?;
                Ok((remain, byte))
            }
            // non-digit is VCHAR minus DIGIT
            &[c @ (0x21..=0x2F | 0x3A..=0x7E), ref remain @ ..] => Ok((remain, c)),
            _ => Err(nom::Err::Error(nom::error::Error::from_error_kind(
                input,
                nom::error::ErrorKind::Escaped,
            ))),
        }
    }

    fn is_non_special(c: u8) -> bool {
        match c {
            // non-special. VCHAR minus DQUOTE, ";", "(", ")" and "\"
            0x21 | 0x23..=0x27 | 0x2A..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E => true,
            _ => false,
        }
    }

    pub(super) fn non_special(input: &[u8]) -> IResult<&[u8], &[u8]> {
        recognize(take_while1(is_non_special))(input)
    }

    fn contiguous_chunk(input: &[u8]) -> IResult<&[u8], DecodingChunk<'_>> {
        alt((
            non_special.map(DecodingChunk::Slice),
            char_escape.map(DecodingChunk::Byte),
        ))(input)
    }

    fn contiguous(input: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
        chunk_1(contiguous_chunk).parse(input)
    }

    fn quoted(input: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
        let wsc = take_while1(|b| b == b' ' || b == b'\t');
        let wsc2 = take_while1(|b| b == b' ' || b == b'\t');
        let wsc_chunk = alt((wsc, preceded(tag(br"\"), wsc2))).map(DecodingChunk::Slice);
        let parser = chunk_1(alt((contiguous_chunk, wsc_chunk)));
        let mut parser = nom::sequence::delimited(tag(b"\""), parser, tag(b"\""));
        parser.parse(input)
    }

    /// A parser as defined by Appendix A of the draft, which describes RFC 1035 § 5.1
    ///
    /// Note: Appendix A says it's not limited to 255 characters
    pub fn parse(input: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
        quoted.or(contiguous).parse(input)
    }

    #[test]
    fn test_char_string_decoding() {
        let mini = |slice| {
            char_escape(slice).map(|(a, b)| (std::str::from_utf8(a).unwrap(), char::from(b)))
        };
        assert_eq!(mini(b"\\044"), Ok(("", ',')));
        let parse = |slice| strings(parse(slice).map(|(a, b)| (a, Cow::into_owned(b))));
        assert!(parse(b"").is_err());
        assert_eq!(parse(b"hello"), Ok(("", "hello".to_owned())));
        assert_eq!(parse(b"hello\\044"), Ok(("", "hello,".to_owned())));
        assert_eq!(parse(br"hello\\"), Ok(("", "hello\\".to_owned())));
        assert_eq!(parse(br"hello\\\\"), Ok(("", "hello\\\\".to_owned())));
        assert_eq!(parse(br"hello\*"), Ok(("", "hello*".to_owned())));
        assert_eq!(parse(br"\,hello\*"), Ok(("", ",hello*".to_owned())));
        assert_eq!(parse(br"\,hello\*("), Ok(("(", ",hello*".to_owned())));
        assert_eq!(parse(b"*;"), Ok((";", "*".to_owned())));
        assert_eq!(parse(b"*\""), Ok(("\"", "*".to_owned())));
        assert_eq!(parse(b"*\""), Ok(("\"", "*".to_owned())));
    }
}

mod value_list_decoding {
    use super::*;

    fn is_item_allowed(c: u8) -> bool {
        match c {
            // item-allowed is OCTET minus "," and "\".
            b',' => false,
            b'\\' => false,
            _ => true,
        }
    }

    pub fn item_allowed(input: &[u8]) -> IResult<&[u8], &[u8]> {
        recognize(take_while1(is_item_allowed))(input)
    }

    fn contiguous_chunk(input: &[u8]) -> IResult<&[u8], DecodingChunk<'_>> {
        alt((
            item_allowed.map(DecodingChunk::Slice),
            tag(r"\,").map(|_| DecodingChunk::Byte(b',')),
            tag(r"\\").map(|_| DecodingChunk::Byte(b'\\')),
        ))(input)
    }

    fn value_within_contiguous(input: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
        chunk_1(contiguous_chunk).parse(input)
    }

    fn values_contiguous(input: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
        nom::multi::separated_list1(tag(b","), value_within_contiguous.map(|x| x.to_vec()))
            .parse(input)
    }

    fn value_within_quotes(input: &[u8]) -> IResult<&[u8], Cow<'_, [u8]>> {
        let wsc = take_while1(|b| b == b' ' || b == b'\t');
        let wsc2 = take_while1(|b| b == b' ' || b == b'\t');
        let wsc_chunk = alt((wsc, preceded(tag(b"\\"), wsc2))).map(DecodingChunk::Slice);
        let mut parser = chunk_1(alt((contiguous_chunk, wsc_chunk)));
        parser.parse(input)
    }

    fn values_quoted(input: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
        let values =
            nom::multi::separated_list1(tag(b","), value_within_quotes.map(|x| x.to_vec()));
        let mut parser = nom::sequence::delimited(tag(b"\""), values, tag(b"\""));
        parser.parse(input)
    }

    pub fn parse(char_decoded: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
        values_quoted.or(values_contiguous).parse(char_decoded)
    }

    #[cfg(test)]
    fn strings(x: IResult<&[u8], Vec<Vec<u8>>>) -> IResult<&str, Vec<String>> {
        x.map(|(remain, output)| {
            (
                std::str::from_utf8(remain).unwrap(),
                output
                    .into_iter()
                    .map(String::from_utf8)
                    .map(Result::unwrap)
                    .collect(),
            )
        })
        .map_err(|x| {
            x.map(|y| {
                <_ as ParseError<&str>>::from_error_kind(
                    std::str::from_utf8(y.input).unwrap(),
                    y.code,
                )
            })
        })
    }

    #[test]
    fn test_parsing() {
        // value lists must be non-empty
        assert!(ValueList::parse(b"").is_err());
        assert_eq!(
            ValueList::parse(br"hello"),
            Ok(vec![b"hello".to_vec()].into())
        );
        assert_eq!(
            ValueList::parse(br"hello\044hello"),
            Ok(vec![b"hello".to_vec(), b"hello".to_vec()].into())
        );
        assert_eq!(
            ValueList::parse(br"hello\\\044hello"),
            Ok(vec![br"hello,hello".to_vec()].into())
        );
        assert_eq!(
            ValueList::parse(br"hello\\\\044"),
            Ok(vec![br"hello\044".to_vec()].into())
        );
        assert_eq!(
            ValueList::parse(br"hello,\\\044"),
            Ok(vec![br"hello".to_vec(), br",".to_vec()].into())
        );
        assert_eq!(
            ValueList::parse(br"hello\\\\,"),
            Err(DecodingError::new(b",")),
        );
        assert_eq!(
            ValueList::parse(br"hello\*"),
            Ok(vec![b"hello*".to_vec()].into())
        );
        assert_eq!(
            ValueList::parse(br"hi\,hello\*"),
            Ok(vec![b"hi".to_vec(), b"hello*".to_vec()].into())
        );
        assert_eq!(
            ValueList::parse(b"\\,hello\\*("),
            Err(DecodingError::new(b"("))
        );
        assert_eq!(ValueList::parse(b"*;"), Err(DecodingError::new(b";")));
        assert_eq!(ValueList::parse(b"*\""), Err(DecodingError::new(b"\"")));
        assert_eq!(ValueList::parse(b"*\""), Err(DecodingError::new(b"\"")));
    }
}
