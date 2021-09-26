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

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct SingleValue {
    pub value: Vec<u8>,
}

fn wrap_iresult_complete<T>(result: IResult<&[u8], T>) -> Result<T, String> {
    result
        .finish()
        .map_err(|e| String::from_utf8_lossy(e.input).into_owned())
        .and_then(|(remain, t)| {
            if remain.is_empty() {
                Ok(t)
            } else {
                Err(String::from_utf8_lossy(remain).into_owned())
            }
        })
}

impl ValueList {
    /// New
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Parses a comma separated list with escaping as defined in Appendix A.1. This variant has
    /// unlimited size for each value.
    pub fn parse(input: impl AsRef<[u8]>) -> Result<Self, String> {
        Self::parse_inner(input.as_ref())
    }

    fn parse_inner(input: &[u8]) -> Result<Self, String> {
        let cow = wrap_iresult_complete(char_string_decoding::parse(input.as_ref()))?;
        let val = wrap_iresult_complete(value_list_decoding::parse(&cow))?;
        Ok(ValueList { values: val })
    }
}

impl SingleValue {
    pub fn parse(input: impl AsRef<[u8]>) -> Result<Self, String> {
        Self::parse_inner(input.as_ref())
    }
    fn parse_inner(input: &[u8]) -> Result<Self, String> {
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
use nom::{Finish, Parser};
use nom::IResult;

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

pub mod escaping {
    use super::*;

    fn iter_parser<I: Copy, O, E>(
        input: I,
        mut parser: impl Parser<I, O, E> + Clone,
    ) -> impl Iterator<Item = Result<O, fmt::Error>> + Clone {
        let mut remain = input;
        core::iter::from_fn(move || match parser.parse(remain) {
            Ok((rest, chunk)) => {
                remain = rest;
                Some(Ok(chunk))
            }
            Err(nom::Err::Error(..)) => None,
            Err(nom::Err::Failure(..)) => Some(Err(fmt::Error)),
            Err(nom::Err::Incomplete(..)) => Some(Err(fmt::Error)),
        })
    }

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
    pub enum EncodingChunk<'a> {
        Slice(&'a [u8]),
        Escape(&'a str),
        Byte(u8),
    }

    mod char_string {
        use super::*;
        fn chunk(remain: &[u8]) -> IResult<&[u8], EncodingChunk<'_>> {
            super::super::char_string_decoding::non_special
                .map(EncodingChunk::Slice)
                .or(tag(br"\").map(|_| EncodingChunk::Escape(r"\\")))
                .or(tag(br",").map(|_| EncodingChunk::Escape(r"\,")))
                .or(single_byte.map(EncodingChunk::Byte))
                .parse(remain)
        }

        pub fn emit_chunks(
            input: &[u8],
        ) -> impl Iterator<Item = Result<EncodingChunk<'_>, fmt::Error>> + Clone {
            iter_parser(input, chunk)
        }
    }

    mod value_list {
        use super::*;
        fn chunk(remain: &[u8]) -> IResult<&[u8], EncodingChunk<'_>> {
            super::super::value_list_decoding::item_allowed
                .map(EncodingChunk::Slice)
                .or(single_byte.map(EncodingChunk::Byte))
                .parse(remain)
        }

        pub fn emit_chunks(
            input: &[u8],
        ) -> impl Iterator<Item = Result<EncodingChunk<'_>, fmt::Error>> + Clone {
            iter_parser(input, chunk)
        }
    }

    fn format_iter<'a, I>(iter: I) -> impl fmt::Display + 'a
    where
        I: Iterator<Item = Result<EncodingChunk<'a>, fmt::Error>> + Clone + 'a,
    {
        display_utils::join_format(iter, "", |chunk, f| match chunk? {
            EncodingChunk::Slice(slice) => {
                // Technically we know this is printable ASCII. is that utf8?
                let string = std::str::from_utf8(slice).map_err(|e| {
                    log::error!("error escaping string: {}", e);
                    fmt::Error
                })?;
                f.write_str(string)?;
                Ok(())
            }
            EncodingChunk::Escape(str) => {
                str.fmt(f)
            }
            EncodingChunk::Byte(byte) => {
                write!(f, "\\{:03}", byte)
            }
        })
    }

    pub fn escape_char_string(
        string: &[u8],
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let chunks = char_string::emit_chunks(string);
        let iter = format_iter(chunks);
        if string.contains(&b' ') {
            write!(f, "\"{}\"", iter)
        } else {
            iter.fmt(f)
        }
    }

    fn escape_values_join<'a>(
        values: impl Iterator<Item = &'a [u8]> + Clone + 'a,
    ) -> Result<Vec<u8>, fmt::Error> {
        // for each value, encode `\`  as `\\` and `,` as `\,`, and join all together with `,`
        let mut vec = Vec::new();
        for value in values {
            let chunks = value_list::emit_chunks(value);
            for encoding_chunk in chunks {
                match encoding_chunk? {
                    EncodingChunk::Slice(slice) => vec.extend_from_slice(slice),
                    EncodingChunk::Escape(str) => vec.extend_from_slice(str.as_bytes()),
                    // doesn't happen
                    EncodingChunk::Byte(byte) => vec.push(byte),
                }
            }
            vec.push(b',');
        }
        vec.pop();
        Ok(vec)
    }

    pub fn encode_value_list<'a>(
        iter: impl Iterator<Item = &'a [u8]> + Clone + 'a,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        let joined = escape_values_join(iter)?;
        escape_char_string(&joined, f)
    }

    impl fmt::Display for ValueList {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            encode_value_list(self.values.iter().map(|val| val.as_slice()), f)
        }
    }

    impl fmt::Display for SingleValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let bytes = self.value.as_slice();
            escape_char_string(bytes, f)
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
    fn test_escaping() {
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
    fn test_escaping() {
        let parse = |slice: &[u8]| ValueList::parse(slice);
        assert!(parse(b"").is_err());
        assert_eq!(
            parse(br"hello"),
            Ok([b"hello"].iter().map(|x| x.to_vec()).collect())
        );
        assert_eq!(
            parse(br"hello\044hello"),
            Ok(vec![br"hello".to_vec(), br"hello".to_vec()].into())
        );
        assert_eq!(
            parse(br"hello\\\044hello"),
            Ok(vec![br"hello,hello".to_vec()].into())
        );
        assert_eq!(
            parse(br"hello\\\\044"),
            Ok(vec![br"hello\044".to_vec()].into())
        );
        assert_eq!(
            parse(br"hello,\\\044"),
            Ok(vec![br"hello".to_vec(), br",".to_vec()].into())
        );
        assert_eq!(parse(br"hello\\\\,"), Err(",".into()),);
        assert_eq!(parse(br"hello\*"), Ok(vec![b"hello*".to_vec()].into()));
        assert_eq!(
            parse(br"hi\,hello\*"),
            Ok(vec![b"hi".to_vec(), b"hello*".to_vec()].into())
        );
        assert_eq!(parse(b"\\,hello\\*("), Err("(".into()));
        assert_eq!(parse(b"*;"), Err(";".into()));
        assert_eq!(parse(b"*\""), Err("\"".into()));
        assert_eq!(parse(b"*\""), Err("\"".into()));
    }
}
