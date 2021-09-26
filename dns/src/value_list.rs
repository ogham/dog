#![allow(dead_code)]

use core::fmt::{self, Display};
use std::io::{Cursor, Read};

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

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct SingleValue {
    pub value: Vec<u8>,
}

impl ValueList {
    /// New
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// Parses a comma separated list with escaping as defined in Appendix A.1. This variant has
    /// unlimited size for each value.
    pub fn parse(input: &str) -> Result<Self, &str> {
        value_list_decoding::parse(input.as_bytes())
            .finish()
            .map_err(|e| std::str::from_utf8(e.input).unwrap())
            .and_then(|(remain, values)| {
                if remain.is_empty() {
                    Ok(ValueList { values })
                } else {
                    Err(std::str::from_utf8(remain).unwrap())
                }
            })
    }

    pub fn read_value_max(
        stated_length: u16,
        cursor: &mut Cursor<&[u8]>,
        single_value_max: usize,
    ) -> Result<Self, WireError> {
        // These methods would be better with Cursor::remaining_slice if it were stable
        let mut buf = vec![0u8; usize::from(stated_length)];
        cursor.read_exact(&mut buf)?;
        let values = value_list_decoding::parse(&buf).no_remaining()?;
        if values.iter().any(|val| val.len() > single_value_max) {
            return Err(WireError::IO);
        } else {
            Ok(Self { values })
        }
    }

    pub fn read_unlimited(
        stated_length: u16,
        cursor: &mut Cursor<&[u8]>,
    ) -> Result<Self, WireError> {
        // These methods would be better with Cursor::remaining_slice if it were stable
        let mut buf = vec![0u8; usize::from(stated_length)];
        cursor.read_exact(&mut buf)?;
        let values = value_list_decoding::parse(&buf).no_remaining()?;
        Ok(Self { values })
    }
}

impl SingleValue {
    pub fn read(stated_length: u16, cursor: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        // These methods would be better with Cursor::remaining_slice if it were stable
        let mut buf = vec![0u8; usize::from(stated_length)];
        cursor.read_exact(&mut buf)?;
        let value = char_string::parse(&buf).no_remaining()?;
        Ok(Self { value })
    }
}

trait NoRemaining<I: InputLength, O, E>: Finish<I, O, E> {
    fn no_remaining(self) -> Result<O, WireError>;
}

impl<T, I: InputLength, O, E> NoRemaining<I, O, E> for T
where
    T: Finish<I, O, E>,
{
    fn no_remaining(self) -> Result<O, WireError> {
        let (i, o) = self.finish().map_err(|_| WireError::IO)?;
        if i.input_len() == 0 {
            Ok(o)
        } else {
            Err(WireError::IO)
        }
    }
}

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::combinator::recognize;
use nom::error::ParseError;
use nom::sequence::preceded;
use nom::{Finish, Parser};
use nom::{IResult, InputLength};

use crate::WireError;

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

fn is_non_special(split_comma: bool, whitespace: bool) -> impl Fn(u8) -> bool {
    move |c: u8| match c {
        b',' if split_comma => false,
        // non-special. VCHAR minus DQUOTE, ";", "(", ")" and "\"
        0x21 | 0x23..=0x27 | 0x2A..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E => true,
        b' ' | b'\t' if whitespace => true,
        _ => false,
    }
}

fn non_special(split_comma: bool, whitespace: bool) -> impl FnMut(&[u8]) -> IResult<&[u8], &[u8]> {
    move |input| recognize(take_while1(is_non_special(split_comma, whitespace)))(input)
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

    fn chunk(
        split_comma: bool,
        whitespace: bool,
    ) -> impl FnMut(&[u8]) -> IResult<&[u8], EscChunk<'_>> + Clone {
        move |remain| {
            non_special(split_comma, whitespace)
                .map(EscChunk::Slice)
                .or(single_byte.map(EscChunk::Byte))
                .parse(remain)
        }
    }

    pub fn emit_chunks(
        input: &[u8],
        split_comma: bool,
        whitespace: bool,
    ) -> impl Iterator<Item = Result<EscChunk<'_>, fmt::Error>> + Clone {
        iter_parser(input, chunk(split_comma, whitespace))
    }

    fn format_iter<'a, I>(iter: I) -> impl fmt::Display + 'a
    where
        I: Iterator<Item = Result<EscChunk<'a>, fmt::Error>> + Clone + 'a,
    {
        display_utils::join_format(iter, "", |chunk, f| match chunk? {
            EscChunk::Slice(slice) => {
                // Technically we know this is printable ASCII. is that utf8?
                let string = std::str::from_utf8(slice).map_err(|e| {
                    log::error!("error escaping string: {}", e);
                    fmt::Error
                })?;
                f.write_str(string)?;
                Ok(())
            }
            EscChunk::Byte(byte) => {
                write!(f, "\\{:03}", byte)
            }
        })
    }

    pub fn format_values_iter<'a>(
        split_comma: bool,
        iter: impl Iterator<Item = &'a [u8]> + Clone,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        // technically this could pull up a false positive, but that's fine, quotes are always valid
        let should_quote = iter
            .clone()
            .any(|val| val.contains(&b' ') || val.contains(&b'\t'));
        if should_quote {
            let joiner = if split_comma { "," } else { "" };
            let iter_fmt = display_utils::join_format(iter, joiner, |value, f| {
                let iter = emit_chunks(value, split_comma, true);
                format_iter(iter).fmt(f)
            });
            write!(f, "\"{}\"", iter_fmt)?;
        } else {
            display_utils::join_format(iter, ",", |value, f| {
                let iter = emit_chunks(value, split_comma, false);
                format_iter(iter).fmt(f)
            })
            .fmt(f)?;
        }
        Ok(())
    }

    impl fmt::Display for ValueList {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            format_values_iter(true, self.values.iter().map(|val| val.as_slice()), f)
        }
    }
    impl fmt::Display for SingleValue {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            format_values_iter(false, core::iter::once(self.value.as_slice()), f)
        }
    }
}

fn char_escape(input: &[u8]) -> IResult<&[u8], u8> {
    let (input, _backslash) = nom::bytes::complete::tag(b"\\")(input)?;
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
pub enum EscChunk<'a> {
    Slice(&'a [u8]),
    Byte(u8),
}

fn chunk_1<'a, F, E>(mut inner: F) -> impl Parser<&'a [u8], Vec<u8>, E>
where
    F: Parser<&'a [u8], EscChunk<'a>, E>,
    E: ParseError<&'a [u8]> + core::fmt::Debug,
{
    move |input| {
        let mut output = Vec::new();
        let parser = |slice| inner.parse(slice);
        let mut iter = nom::combinator::iterator(input, parser);
        let i = &mut iter;
        let mut success = false;
        for chunk in i {
            success = true;
            match chunk {
                EscChunk::Slice(slice) => output.extend_from_slice(slice),
                EscChunk::Byte(byte) => output.push(byte),
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

mod char_string {
    use super::*;
    fn contiguous_chunk(input: &[u8]) -> IResult<&[u8], EscChunk<'_>> {
        alt((
            non_special(false, false).map(EscChunk::Slice),
            char_escape.map(EscChunk::Byte),
        ))(input)
    }

    fn contiguous(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        chunk_1(contiguous_chunk).parse(input)
    }

    fn quoted(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        let wsc = take_while1(|b| b == b' ' || b == b'\t');
        let wsc2 = take_while1(|b| b == b' ' || b == b'\t');
        let wsc_chunk = alt((wsc, preceded(tag(b"\\"), wsc2))).map(EscChunk::Slice);
        let parser = chunk_1(alt((contiguous_chunk, wsc_chunk)));
        let mut parser = nom::sequence::delimited(tag(b"\""), parser, tag(b"\""));
        parser.parse(input)
    }

    /// A parser as defined by Appendix A of the draft, which describes RFC 1035 § 5.1
    ///
    /// Note: Appendix A says it's not limited to 255 characters
    pub fn parse(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        quoted.or(contiguous).parse(input)
    }

    #[test]
    fn test_escaping() {
        let mini = |slice| {
            char_escape(slice).map(|(a, b)| (std::str::from_utf8(a).unwrap(), char::from(b)))
        };
        assert_eq!(mini(b"\\044"), Ok(("", ',')));
        let parse = |slice| strings(contiguous(slice));
        assert!(parse(b"").is_err());
        assert_eq!(parse(b"hello"), Ok(("", "hello".to_owned())));
        assert_eq!(parse(b"hello\\044"), Ok(("", "hello,".to_owned())));
        assert_eq!(parse(b"hello\\\\"), Ok(("", "hello\\".to_owned())));
        assert_eq!(parse(b"hello\\\\\\\\"), Ok(("", "hello\\\\".to_owned())));
        assert_eq!(parse(b"hello\\*"), Ok(("", "hello*".to_owned())));
        assert_eq!(parse(b"\\,hello\\*"), Ok(("", ",hello*".to_owned())));
        assert_eq!(parse(b"\\,hello\\*("), Ok(("(", ",hello*".to_owned())));
        assert_eq!(parse(b"*;"), Ok((";", "*".to_owned())));
        assert_eq!(parse(b"*\""), Ok(("\"", "*".to_owned())));
        assert_eq!(parse(b"*\""), Ok(("\"", "*".to_owned())));
    }
}

mod value_list_decoding {
    use super::*;

    fn contiguous_chunk(input: &[u8]) -> IResult<&[u8], EscChunk<'_>> {
        alt((
            non_special(true, false).map(EscChunk::Slice),
            char_escape.map(EscChunk::Byte),
        ))(input)
    }

    fn value_within_contiguous(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        chunk_1(contiguous_chunk).parse(input)
    }

    fn values_contiguous(input: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
        nom::multi::separated_list1(tag(b","), value_within_contiguous).parse(input)
    }

    fn value_within_quotes(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        let wsc = take_while1(|b| b == b' ' || b == b'\t');
        let wsc2 = take_while1(|b| b == b' ' || b == b'\t');
        let wsc_chunk = alt((wsc, preceded(tag(b"\\"), wsc2))).map(EscChunk::Slice);
        let mut parser = chunk_1(alt((contiguous_chunk, wsc_chunk)));
        parser.parse(input)
    }

    fn values_quoted(input: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
        let values = nom::multi::separated_list1(tag(b","), value_within_quotes);
        let mut parser = nom::sequence::delimited(tag(b"\""), values, tag(b"\""));
        parser.parse(input)
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Vec<Vec<u8>>> {
        values_quoted.or(values_contiguous).parse(input)
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
        let mini = |slice| {
            char_escape(slice).map(|(a, b)| (std::str::from_utf8(a).unwrap(), char::from(b)))
        };
        assert_eq!(mini(b"\\044"), Ok(("", ',')));

        let parse = |slice| strings(values_contiguous(slice));
        assert!(parse(b"").is_err());
        assert_eq!(parse(b"hello"), Ok(("", vec!["hello".to_owned()])));
        assert_eq!(parse(b"hello\\044"), Ok(("", vec!["hello,".to_owned()])));
        assert_eq!(
            parse(b"hello\\\\\\044"),
            Ok(("", vec!["hello\\,".to_owned()]))
        );
        assert_eq!(
            parse(b"hello,\\\\\\044"),
            Ok(("", vec!["hello".to_owned(), "\\,".to_owned()]))
        );
        assert_eq!(
            parse(b"hello\\\\\\\\,"),
            Ok((",", vec!["hello\\\\".to_owned()]))
        );
        assert_eq!(parse(b"hello\\*"), Ok(("", vec!["hello*".to_owned()])));
        assert_eq!(parse(b"\\,hello\\*"), Ok(("", vec![",hello*".to_owned()])));
        assert_eq!(
            parse(b"\\,hello\\*("),
            Ok(("(", vec![",hello*".to_owned()]))
        );
        assert_eq!(parse(b"*;"), Ok((";", vec!["*".to_owned()])));
        assert_eq!(parse(b"*\""), Ok(("\"", vec!["*".to_owned()])));
        assert_eq!(parse(b"*\""), Ok(("\"", vec!["*".to_owned()])));
    }
}
