#![allow(dead_code)]

use std::io::Cursor;

/// Parameters to a SVCB/HTTPS record can be multi-valued.
/// This is a fancy comma-separated list, where escaped commas \, and \044 do not separate
/// values.
///
/// # References:
///
/// [Draft RFC](https://tools.ietf.org/id/draft-ietf-dnsop-svcb-https-02.html#name-the-svcb-record-type), section A.1
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct ValueList {
    values: Vec<Vec<u8>>,
}

impl ValueList {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    /// for tests
    pub fn encode(input: &str) -> Self {
        todo!()
    }
}

fn read_string(_list: &mut ValueList, _c: &mut Cursor<&[u8]>) {
    todo!()
}

use nom::Parser;
use nom::branch::alt;
use nom::combinator::recognize;
use nom::error::ParseError;
use nom::sequence::preceded;
use nom::IResult;
use nom::bytes::complete::{tag, take_while1};

/// A parser as defined by Appendix A of the draft, which describes RFC 1035 § 5.1
///
/// Note: Appendix A says it's not limited to 255 characters
pub fn parse_char_string(buf: &[u8]) -> IResult<&[u8], Vec<u8>> {
    if buf.starts_with(b"\"") {
        quoted(buf)
    } else {
        contiguous(buf)
    }
}

#[cfg(test)]
fn strings(x: IResult<&[u8], Vec<u8>>) -> IResult<&str, String> {
    x
        .map(|(remain, output)| {
            (std::str::from_utf8(remain).unwrap(), String::from_utf8(output).unwrap())
        })
        .map_err(|x| x.map(|y| <_ as ParseError<&str>>::from_error_kind(std::str::from_utf8(y.input).unwrap(), y.code)))
}

#[test]
fn test_escaping() {
    // let parse = |slice| strings(non_special(slice).map(|(a, b)| (a, Vec::from(b))));
    let mini = |slice| char_escape(slice).map(|(a, b)| (std::str::from_utf8(a).unwrap(), char::from(b)));
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

fn non_special(input: &[u8]) -> IResult<&[u8], &[u8]> {
    fn is_non_special(c: u8) -> bool {
        match c {
            // 
            //
            //
            //
            //
            //
            //
            // TODO: remove comma from this to make a value-list
            //
            //
            //
            //
            //
            //
            //
            // non-special. VCHAR minus DQUOTE, ";", "(", ")" and "\"
            0x21 | 0x23..=0x27 | 0x2A..=0x3A | 0x3C..=0x5B | 0x5D..=0x7E => true,
            _ => false,
        }
    }
    recognize(take_while1(is_non_special))(input)
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
        &[c @ (0x21..=0x2F | 0x3A..=0x7E), ref remain @ ..] => {
            Ok((remain, c))
        }
        _ => Err(nom::Err::Error(nom::error::Error::from_error_kind(input, nom::error::ErrorKind::Escaped))),
    }
}

fn dec_octet(buf: &[u8], zero_one_or_two: u8) -> IResult<&[u8], u8> {
    let (hundreds, tens, ones, rest) = match zero_one_or_two {
        hundreds @ (0 | 1) => match buf {
            [tens @ b'0'..=b'9', ones @ b'0'..=b'9', rest @ ..] => (hundreds, tens - b'0', ones - b'0', rest),
            _ => return Err(nom::Err::Error(nom::error::Error::from_error_kind(buf, nom::error::ErrorKind::Escaped))),
        },
        hundreds @ 2 => match buf {
            [tens @ b'0'..=b'4', ones @ b'0'..=b'9', rest @ ..] | [tens @ b'5', ones @ b'0'..=b'5', rest @ ..] => {
                (hundreds, tens - b'0', ones - b'0', rest)
            }
            _ => return Err(nom::Err::Error(nom::error::Error::from_error_kind(buf, nom::error::ErrorKind::Escaped))),
        },
        _ => return Err(nom::Err::Error(nom::error::Error::from_error_kind(buf, nom::error::ErrorKind::Escaped))),
    };
    let byte = hundreds * 100 + tens * 10 + ones;
    Ok((rest, byte))
}

#[derive(Debug)]
enum EscChunk<'a> {
    Slice(&'a [u8]),
    Byte(u8)
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
            Err(nom::Err::Error(E::from_error_kind(input, nom::error::ErrorKind::Eof)))
        }
    }
}

fn contiguous_chunk(input: &[u8]) -> IResult<&[u8], EscChunk<'_>> {
    alt((non_special.map(EscChunk::Slice), char_escape.map(EscChunk::Byte)))(input)
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
