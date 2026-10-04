//! Just enough HTTP/2 (RFC 9113) to send one DNS-over-HTTPS request and read
//! its response, for the servers that choose HTTP/2 when offered it, and for
//! those, such as Quad9’s, that speak nothing else.
//!
//! dog opens a connection for each request and closes it afterwards, so it
//! only ever uses one stream, and has no need of the header compression
//! state (RFC 7541) that a longer connection would build up: it sends every
//! header uncompressed, and decodes only the first field of the response’s
//! headers, which must be its status.

use std::io::{Read, Write};
use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::Error;
use super::address::HttpsUrl;
use super::https::{host_header, MAX_BODY, USER_AGENT};
use super::{net, tcp};


/// What every HTTP/2 connection from a client starts with (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The largest frame payload either side may send without the other agreeing
/// to more, which dog never does (RFC 9113 §4.2).
const MAX_FRAME: usize = 16_384;

/// The stream dog sends its one request on: the first a client may use.
const STREAM: u32 = 1;

// Frame types (RFC 9113 §6).
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;

// Frame flags.
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

/// dog’s settings: `SETTINGS_ENABLE_PUSH` (2) turned off, because it has no
/// use for responses it did not ask for.
const NO_PUSH: [u8; 6] = [ 0, 2, 0, 0, 0, 0 ];

/// The names of the HTTP/2 error codes (RFC 9113 §7).
const ERROR_CODES: [&str; 14] = [
    "NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT",
    "STREAM_CLOSED", "FRAME_SIZE_ERROR", "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR",
    "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED",
];

/// The statuses in entries 8 to 14 of the HPACK static table (RFC 7541
/// appendix A), which is how servers usually send the common ones.
const STATIC_STATUSES: [u16; 7] = [ 200, 204, 206, 304, 400, 404, 500 ];

/// The Huffman codes of the ten digits, as (code, length in bits) (RFC 7541
/// appendix B). A status is three digits, so no other symbol can be part of
/// a valid one.
const HUFFMAN_DIGITS: [(u32, u32); 10] = [
    (0b0_0000, 5), (0b0_0001, 5), (0b0_0010, 5), (0b01_1001, 6), (0b01_1010, 6),
    (0b01_1011, 6), (0b01_1100, 6), (0b01_1101, 6), (0b01_1110, 6), (0b01_1111, 6),
];


/// Sends a request as an HTTP/2 POST, and reads the answer from the response
/// body. Returns an error if it does not answer the request.
pub(crate) fn exchange(stream: &mut (impl Read + Write), url: &HttpsUrl<'_>, request: &Request, timeout: Duration) -> Result<Response, Error> {
    let bytes_to_send = request_bytes(url, &request.to_bytes()?)?;
    info!("Sending {} bytes of data to {}:{} over HTTP/2", bytes_to_send.len(), url.host, url.port);
    send(stream, &bytes_to_send, timeout)?;

    let body = read_body(stream, timeout)?;
    debug!("HTTP/2 body has {} bytes", body.len());

    let response = Response::from_bytes(&body)?;
    request.check_response(&response)?;
    Ok(response)
}

fn send(stream: &mut impl Write, bytes: &[u8], timeout: Duration) -> Result<(), Error> {
    stream.write_all(bytes).and_then(|()| stream.flush()).map_err(|e| net::io_error(e, timeout))
}

/// Everything dog sends: the connection preface and its settings, then the
/// request, which is its headers and the DNS message as its body.
pub(crate) fn request_bytes(url: &HttpsUrl<'_>, body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend(frame(SETTINGS, 0, 0, &NO_PUSH)?);
    bytes.extend(frame(HEADERS, END_HEADERS, STREAM, &header_block(url, body.len()))?);

    let chunks = if body.is_empty() { vec![ body ] } else { body.chunks(MAX_FRAME).collect::<Vec<_>>() };
    for (number, chunk) in chunks.iter().enumerate() {
        let flags = if number + 1 == chunks.len() { END_STREAM } else { 0 };
        bytes.extend(frame(DATA, flags, STREAM, chunk)?);
    }

    Ok(bytes)
}

/// One frame: its length, type, flags, and stream, then its payload (RFC
/// 9113 §4.1). A payload too long for one frame can only come from a very
/// long URL, since a DNS message is split into as many frames as it needs.
fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_FRAME {
        return Err(malformed(format!("The request needs a frame of {} bytes, more than the {MAX_FRAME} allowed", payload.len())));
    }

    let length = payload.len().to_be_bytes();
    let mut bytes = Vec::with_capacity(9 + payload.len());
    bytes.extend_from_slice(&length[length.len() - 3 ..]);
    bytes.extend_from_slice(&[ kind, flags ]);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// The request’s headers, the same as the HTTP/1.1 transport sends. The
/// method and scheme are single bytes that index the static table; every
/// other field has its name from the static table and its value written
/// out, never Huffman-coded and never added to a table (RFC 7541 §6.2.2),
/// so that no compression state is needed at either end.
fn header_block(url: &HttpsUrl<'_>, body_length: usize) -> Vec<u8> {
    let mut block = vec![ 0x83, 0x87 ];  // :method POST, :scheme https
    let fields = [
        (1, host_header(url)),                        // :authority
        (4, url.path.to_owned()),                     // :path
        (31, "application/dns-message".to_owned()),   // content-type
        (19, "application/dns-message".to_owned()),   // accept
        (58, USER_AGENT.to_owned()),                  // user-agent
        (28, body_length.to_string()),                // content-length
    ];

    for (name_index, value) in fields {
        block.extend(integer(name_index, 4, 0x00));
        block.extend(integer(value.len(), 7, 0x00));
        block.extend_from_slice(value.as_bytes());
    }

    block
}

/// An integer in HPACK’s format with an N-bit prefix (RFC 7541 §5.1): in the
/// prefix if it fits, and otherwise seven bits at a time after it. The bits
/// above the prefix are `high_bits`.
fn integer(value: usize, prefix_bits: u32, high_bits: u8) -> Vec<u8> {
    let limit = (1_usize << prefix_bits) - 1;
    if value < limit {
        return vec![ high_bits | low_byte(value) ];
    }

    let mut bytes = vec![ high_bits | low_byte(limit) ];
    let mut rest = value - limit;
    while rest >= 0x80 {
        bytes.push(low_byte(rest) | 0x80);
        rest >>= 7;
    }
    bytes.push(low_byte(rest));
    bytes
}

/// The lowest eight bits of a number.
fn low_byte(value: usize) -> u8 {
    value.to_le_bytes()[0]
}


/// One frame from the server.
#[derive(Debug)]
struct Frame {
    kind: u8,
    flags: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// What has arrived of the response so far.
#[derive(Debug, Default)]
struct Incoming {

    /// Whether the headers with the final status have arrived.
    headers: bool,

    /// The body so far.
    body: Vec<u8>,

    /// Whether the server has said the response is over.
    ended: bool,
}

/// Reads frames until the response is over, answering the server’s settings
/// and pings as they come, and returns the body. The status must be 200 OK.
fn read_body(stream: &mut (impl Read + Write), timeout: Duration) -> Result<Vec<u8>, Error> {
    let mut incoming = Incoming::default();
    while ! incoming.ended {
        let frame = read_frame(stream, timeout)?;
        if let Some(reply) = handle(&mut incoming, &frame)? {
            send(stream, &reply, timeout)?;
        }
    }

    Ok(incoming.body)
}

fn read_frame(stream: &mut impl Read, timeout: Duration) -> Result<Frame, Error> {
    let mut head = [0; 9];
    tcp::read_fully(stream, &mut head, timeout)?;

    let length = usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
    if length > MAX_FRAME {
        return Err(malformed(format!("The server sent a frame of {length} bytes, more than the {MAX_FRAME} allowed")));
    }

    let mut payload = vec![0; length];
    tcp::read_fully(stream, &mut payload, timeout)?;

    let stream = u32::from_be_bytes([ head[5], head[6], head[7], head[8] ]) & 0x7FFF_FFFF;
    trace!("Received a frame of type {} with flags {:#04x} on stream {stream}, {length} bytes long", head[3], head[4]);
    Ok(Frame { kind: head[3], flags: head[4], stream, payload })
}

/// Deals with one frame. Returns a frame to send back, if the server needs
/// an answer, or an error if the response cannot be used. Frames that dog
/// has no use for, such as window updates, and frames of types newer than
/// it knows, are ignored, as they must be (RFC 9113 §4.1).
fn handle(incoming: &mut Incoming, frame: &Frame) -> Result<Option<Vec<u8>>, Error> {
    let ours = frame.stream == STREAM;
    match frame.kind {
        SETTINGS if frame.flags & ACK == 0  => self::frame(SETTINGS, ACK, 0, &[]).map(Some),
        PING if frame.flags & ACK == 0      => self::frame(PING, ACK, 0, &frame.payload).map(Some),
        GOAWAY                              => Err(stopped("closed the connection", frame.payload.get(4 .. 8))),
        RST_STREAM if ours                  => Err(stopped("cancelled the request", frame.payload.get(.. 4))),
        HEADERS if ours                     => headers(incoming, frame).map(|()| None),
        DATA if ours                        => data(incoming, frame).map(|()| None),
        PUSH_PROMISE                        => Err(malformed("The server pushed a response after being told not to")),
        _                                   => Ok(None),
    }
}

/// The error for a server that gave up on the request, with its reason, if
/// it gave one.
fn stopped(what: &str, code: Option<&[u8]>) -> Error {
    let Some(code) = code.and_then(|bytes| <[u8; 4]>::try_from(bytes).ok()).map(u32::from_be_bytes) else {
        return malformed(format!("The server {what}"));
    };

    match usize::try_from(code).ok().and_then(|index| ERROR_CODES.get(index)) {
        Some(name) => malformed(format!("The server {what} (HTTP/2 error {name})")),
        None       => malformed(format!("The server {what} (HTTP/2 error code {code:#x})")),
    }
}

/// The response’s headers, whose status must be 200 OK. Informational
/// responses (1xx) can come before the real one, and are skipped; a second
/// block of headers after the body holds trailers, which dog has no use for.
fn headers(incoming: &mut Incoming, frame: &Frame) -> Result<(), Error> {
    let ends = frame.flags & END_STREAM != 0;
    if incoming.headers {
        incoming.ended = ends;
        return Ok(());
    }

    match status(content(frame)?)? {
        200 => {
            incoming.headers = true;
            incoming.ended = ends;
            Ok(())
        }
        100 ..= 199 => Ok(()),
        code => Err(Error::WrongHttpStatus(code, None)),
    }
}

fn data(incoming: &mut Incoming, frame: &Frame) -> Result<(), Error> {
    if ! incoming.headers {
        return Err(malformed("The response body came before its headers"));
    }

    incoming.body.extend_from_slice(content(frame)?);
    if incoming.body.len() > MAX_BODY {
        return Err(malformed(format!("The response body is too long (more than {MAX_BODY} bytes)")));
    }

    incoming.ended = frame.flags & END_STREAM != 0;
    Ok(())
}

/// A HEADERS or DATA frame’s payload, without the padding and priority that
/// its flags say it has (RFC 9113 §6.1, §6.2).
fn content(frame: &Frame) -> Result<&[u8], Error> {
    let (padding, rest) = if frame.flags & PADDED == 0 {
        (0, &frame.payload[..])
    }
    else {
        let (&length, rest) = frame.payload.split_first().ok_or_else(too_short)?;
        (usize::from(length), rest)
    };

    let rest = if frame.kind == HEADERS && frame.flags & PRIORITY != 0 { rest.get(5 ..).ok_or_else(too_short)? } else { rest };
    let end = rest.len().checked_sub(padding).ok_or_else(too_short)?;
    Ok(&rest[.. end])
}

fn too_short() -> Error {
    malformed("A frame is too short for the padding or priority its flags say it has")
}


/// The status, from the start of the response’s header block. Pseudo-header
/// fields come before any others (RFC 9113 §8.3), and a response has only
/// `:status`, so it has to be the first field, after any changes to the
/// size of the dynamic table (RFC 7541 §4.2). The dynamic table is empty
/// until the first field has been read, so the status can only be in the
/// static table or written out.
fn status(block: &[u8]) -> Result<u16, Error> {
    let field = first_field(block)?;
    if field[0] & 0x80 != 0 {
        return static_status(read_integer(field, 7)?.0);
    }

    // A field written out, with or without being added to the table: the
    // prefix of its name’s index is six bits for one, and four for the other.
    // Its name must be `:status`, whichever of those entries names it.
    let prefix_bits = if field[0] & 0x40 != 0 { 6 } else { 4 };
    let (index, used) = read_integer(field, prefix_bits)?;
    static_status(index)?;
    parse_status(&string(&field[used ..])?)
}

/// The first field of a header block, after any changes to the size of the
/// dynamic table.
fn first_field(block: &[u8]) -> Result<&[u8], Error> {
    let mut at = 0;
    while block.get(at).is_some_and(|byte| byte & 0xE0 == 0x20) {
        at += read_integer(&block[at ..], 5)?.1;
    }

    block.get(at ..).filter(|field| ! field.is_empty()).ok_or_else(|| malformed("The response has no status"))
}

/// The status in an entry of the static table, which must be one of the
/// `:status` entries.
fn static_status(index: usize) -> Result<u16, Error> {
    index.checked_sub(8).and_then(|i| STATIC_STATUSES.get(i)).copied().ok_or_else(|| not_the_status(index))
}

fn not_the_status(index: usize) -> Error {
    malformed(format!("The response headers start with field {index}, not the status"))
}

/// Reads an integer in HPACK’s format with an N-bit prefix from the start of
/// `bytes`, and returns it with how many bytes it took up. Only lengths and
/// indexes are read this way, so anything over 28 bits is refused.
fn read_integer(bytes: &[u8], prefix_bits: u32) -> Result<(usize, usize), Error> {
    let limit = (1_usize << prefix_bits) - 1;
    let first = usize::from(*bytes.first().ok_or_else(cut_short)?) & limit;
    if first < limit {
        return Ok((first, 1));
    }

    let mut value = first;
    for (used, &byte) in bytes.iter().enumerate().skip(1).take(4) {
        value += usize::from(byte & 0x7F) << (7 * (used - 1));
        if byte & 0x80 == 0 {
            return Ok((value, used + 1));
        }
    }

    Err(malformed("A number in the response headers is too long, or cut short"))
}

/// Reads a string (RFC 7541 §5.2): its length, whether it is Huffman-coded,
/// and its bytes.
fn string(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let (length, used) = read_integer(bytes, 7)?;
    let raw = bytes.get(used ..).and_then(|rest| rest.get(.. length)).ok_or_else(cut_short)?;
    if bytes[0] & 0x80 == 0 { Ok(raw.to_vec()) } else { huffman_digits(raw) }
}

fn cut_short() -> Error {
    malformed("The response headers are cut short")
}

/// Decodes a Huffman-coded status (RFC 7541 §5.2), which can only hold
/// digits. Whatever is left over at the end must be padding: fewer than
/// eight bits, all of them ones.
fn huffman_digits(coded: &[u8]) -> Result<Vec<u8>, Error> {
    let mut digits = Vec::new();
    let (mut code, mut length) = (0_u32, 0_u32);

    for bit in coded.iter().flat_map(|byte| (0 .. 8).rev().map(move |shift| byte >> shift & 1)) {
        code = code << 1 | u32::from(bit);
        length += 1;
        if let Some(digit) = HUFFMAN_DIGITS.iter().position(|&known| known == (code, length)) {
            digits.push(b"0123456789"[digit]);
            (code, length) = (0, 0);
        }
        else if length > 7 {
            return Err(not_huffman_digits());
        }
    }

    if code == (1 << length) - 1 { Ok(digits) } else { Err(not_huffman_digits()) }
}

fn not_huffman_digits() -> Error {
    malformed("The response status is not Huffman-coded digits")
}

fn parse_status(value: &[u8]) -> Result<u16, Error> {
    std::str::from_utf8(value).ok()
        .filter(|text| text.len() == 3 && text.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| malformed(format!("The response status {:?} is not three digits", String::from_utf8_lossy(value))))
}

fn malformed(why: impl Into<String>) -> Error {
    Error::MalformedHttp(why.into())
}


#[cfg(test)]
mod test {
    use super::*;
    use std::io::{self, Cursor};
    use crate::net::Deadline;
    use crate::test_util::{a_example, SHORT};
    use test_support::{fixtures, wire};
    use test_support::mock::{self, Http2};
    use test_support::wire::H2Frame;

    /// A stream that reads a server’s bytes from one buffer, and writes dog’s
    /// to another, or fails every write.
    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        writable: bool,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.writable { self.output.write(buf) } else { Err(io::ErrorKind::BrokenPipe.into()) }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn duplex(response: Vec<u8>) -> Duplex {
        Duplex { input: Cursor::new(response), output: Vec::new(), writable: true }
    }

    /// Reads a response, returning the body and whatever dog sent back.
    fn read(response: Vec<u8>) -> (Result<Vec<u8>, Error>, Vec<H2Frame>) {
        let mut stream = duplex(response);
        let result = read_body(&mut stream, SHORT);
        (result, wire::h2_frames(&stream.output))
    }

    fn body_of(response: Vec<u8>) -> Result<Vec<u8>, Error> {
        read(response).0
    }

    fn malformed(response: Vec<u8>) -> String {
        match body_of(response) { Err(Error::MalformedHttp(why)) => why, other => panic!("expected malformed HTTP/2, got {other:?}") }
    }

    fn url(host: &str) -> HttpsUrl<'_> {
        HttpsUrl { host, port: 443, path: "/dns-query" }
    }

    fn settings_ack() -> H2Frame {
        H2Frame { kind: wire::H2_SETTINGS, flags: wire::H2_ACK, stream: 0, payload: Vec::new() }
    }

    fn frame_on(stream: u32, kind: u8, flags: u8, payload: &[u8]) -> H2Frame {
        H2Frame { kind, flags, stream, payload: payload.to_vec() }
    }

    /// A response with `extra` put in front of its first frame of a type.
    fn with_before(response: &[u8], kind: u8, extra: H2Frame) -> Vec<u8> {
        let mut extra = Some(extra);
        wire::map_h2_frames(response, |frame| {
            match extra.take_if(|_| frame.kind == kind) {
                Some(extra) => vec![ extra, frame ],
                None        => vec![ frame ],
            }
        })
    }

    /// Google’s real answer, with `extra` put in front of its first frame of
    /// the given type.
    fn google_with_before(kind: u8, extra: H2Frame) -> Vec<u8> {
        with_before(&fixtures::h2_response("doh2-google"), kind, extra)
    }

    /// Google’s real 415 response, whose status is the written-out field
    /// `08 03 "415"`, with that field replaced.
    fn google_415_with_status(field: &[u8]) -> Vec<u8> {
        wire::map_h2_frames(&fixtures::h2_response("doh2-google-415"), |mut frame| {
            if frame.kind == wire::H2_HEADERS {
                assert!(frame.payload.starts_with(b"\x08\x03415"), "{:02x?}", &frame.payload[.. 5]);
                frame.payload = [ field, &frame.payload[5 ..] ].concat();
            }
            vec![ frame ]
        })
    }

    fn status_of(response: Vec<u8>) -> Option<u16> {
        match body_of(response) {
            Ok(_) => Some(200),
            Err(Error::WrongHttpStatus(code, None)) => Some(code),
            Err(_) => None,
        }
    }

    // ---- the request ----

    /// dog’s request is byte for byte the one the capture script sent.
    #[test]
    fn the_request_matches_what_was_captured() {
        for (name, host, path) in [ ("doh2-cloudflare", "cloudflare-dns.com", "/dns-query"), ("doh2-google", "dns.google", "/dns-query"),
                                    ("doh2-quad9", "dns.quad9.net", "/dns-query"), ("doh2-google-404", "dns.google", "/nope") ] {
            let captured = fixtures::h2_request(name);
            let url = HttpsUrl { host, port: 443, path };
            assert_eq!(request_bytes(&url, &wire::h2_body(&captured)).unwrap(), captured, "{name}");
        }
    }

    #[test]
    fn a_long_body_is_split_into_frames() {
        let frames = wire::h2_frames(&request_bytes(&url("localhost"), &vec![ 7; 20_000 ]).unwrap());
        let data = frames.iter().filter(|f| f.kind == wire::H2_DATA).map(|f| (f.payload.len(), f.flags)).collect::<Vec<_>>();
        assert_eq!(data, [ (16_384, 0), (3_616, wire::H2_END_STREAM) ]);
    }

    #[test]
    fn an_empty_body_still_ends_the_stream() {
        let frames = wire::h2_frames(&request_bytes(&url("localhost"), &[]).unwrap());
        assert_eq!(frames.last(), Some(&frame_on(1, wire::H2_DATA, wire::H2_END_STREAM, &[])));
    }

    #[test]
    fn a_url_too_long_for_one_frame() {
        let path = format!("/{}", "a".repeat(20_000));
        let url = HttpsUrl { host: "localhost", port: 443, path: &path };
        assert!(matches!(request_bytes(&url, &[ 1, 2 ]), Err(Error::MalformedHttp(why)) if why.starts_with("The request needs a frame of 200")));
    }

    /// The examples of RFC 7541 appendix C.1.
    #[test]
    fn integers() {
        assert_eq!(integer(10, 5, 0), [ 0x0a ]);
        assert_eq!(integer(1337, 5, 0), [ 0x1f, 0x9a, 0x0a ]);
        assert_eq!(integer(42, 8, 0), [ 42 ]);
        assert_eq!(integer(31, 5, 0xe0), [ 0xff, 0x00 ]);
        assert_eq!(read_integer(&[ 0x1f, 0x9a, 0x0a ], 5).unwrap(), (1337, 3));
        assert_eq!(read_integer(&[ 0xea ], 5).unwrap(), (10, 1));
    }

    // ---- real responses ----

    #[test]
    fn real_answers() {
        for name in [ "doh2-cloudflare", "doh2-google", "doh2-quad9" ] {
            let response = fixtures::h2_response(name);
            let (body, sent) = read(response.clone());
            let body = body.unwrap();
            assert_eq!(body, wire::h2_body(&response), "{name}");
            assert_eq!(Response::from_bytes(&body).unwrap().answers.len(), 1, "{name}");

            // Each server starts with its settings, which dog acknowledges.
            assert_eq!(sent, [ settings_ack() ], "{name}");
        }
    }

    /// Google and Quad9 send 404 from the static table; Google sends 415
    /// written out, and Cloudflare sends it written out and added to the
    /// table.
    #[test]
    fn real_error_statuses() {
        assert_eq!(status_of(fixtures::h2_response("doh2-google-404")), Some(404));
        assert_eq!(status_of(fixtures::h2_response("doh2-google-415")), Some(415));
        assert_eq!(status_of(fixtures::h2_response("doh2-cloudflare-415")), Some(415));
    }

    // ---- statuses written in other ways ----

    /// No server captured Huffman-codes its status, but any may. The bytes
    /// are what Go’s HPACK encoder writes for “415” and “200”, and its
    /// decoder reads `08 83 68 2d ff` as `:status 415`.
    #[test]
    fn huffman_coded_statuses() {
        assert_eq!(status_of(google_415_with_status(&[ 0x08, 0x83, 0x68, 0x2d, 0xff ])), Some(415));
        assert_eq!(status_of(google_415_with_status(&[ 0x08, 0x82, 0x10, 0x01 ])), Some(200));
    }

    #[test]
    fn statuses_written_out_every_way() {
        assert_eq!(status_of(google_415_with_status(b"\x48\x03415")), Some(415));   // added to the table
        assert_eq!(status_of(google_415_with_status(b"\x18\x03415")), Some(415));   // never to be added
        assert_eq!(status_of(google_415_with_status(b"\x0e\x03415")), Some(415));   // named by entry 14
    }

    #[test]
    fn table_size_changes_before_the_status() {
        assert_eq!(status_of(google_415_with_status(b"\x20\x08\x03415")), Some(415));
        assert_eq!(status_of(google_415_with_status(b"\x3f\xe1\x1f\x08\x03415")), Some(415));
    }

    #[test]
    fn headers_that_do_not_start_with_the_status() {
        assert_eq!(malformed(google_415_with_status(&[ 0x82 ])), "The response headers start with field 2, not the status");
        assert_eq!(malformed(google_415_with_status(&[ 0xbe ])), "The response headers start with field 62, not the status");
        assert_eq!(malformed(google_415_with_status(b"\x00\x07:status\x03415")), "The response headers start with field 0, not the status");
        assert_eq!(malformed(google_415_with_status(b"\x04\x01/")), "The response headers start with field 4, not the status");
    }

    #[test]
    fn statuses_that_are_not_three_digits() {
        assert_eq!(malformed(google_415_with_status(b"\x08\x032x0")), r#"The response status "2x0" is not three digits"#);
        assert_eq!(malformed(google_415_with_status(b"\x08\x0220")), r#"The response status "20" is not three digits"#);
        assert_eq!(malformed(google_415_with_status(&[ 0x08, 0x81, 0x1f ])), "The response status is not Huffman-coded digits");
        assert_eq!(malformed(google_415_with_status(&[ 0x08, 0x81, 0x68 ])), "The response status is not Huffman-coded digits");
    }

    #[test]
    fn header_blocks_cut_short() {
        // A value 382 bytes long, in a block with far fewer left.
        assert_eq!(malformed(google_415_with_status(b"\x08\x7f\xff\x01")), "The response headers are cut short");
        assert_eq!(malformed(google_415_with_status(&[ 0x0f, 0xff, 0xff, 0xff, 0xff, 0x01 ])), "A number in the response headers is too long, or cut short");
        let empty = wire::map_h2_frames(&fixtures::h2_response("doh2-google-415"), |mut frame| {
            if frame.kind == wire::H2_HEADERS { frame.payload.clear(); }
            vec![ frame ]
        });
        assert_eq!(malformed(empty), "The response has no status");
    }

    // ---- frames around the answer ----

    #[test]
    fn an_informational_response_before_the_answer() {
        let early_hints = frame_on(1, wire::H2_HEADERS, wire::H2_END_HEADERS, b"\x08\x03103");
        assert!(body_of(google_with_before(wire::H2_HEADERS, early_hints)).is_ok());
    }

    /// Google ends its answer with an empty DATA frame; here that is trailers.
    #[test]
    fn trailers_after_the_body() {
        let response = wire::map_h2_frames(&fixtures::h2_response("doh2-google"), |frame| {
            if frame.kind == wire::H2_DATA && frame.payload.is_empty() {
                vec![ frame_on(1, wire::H2_HEADERS, wire::H2_END_HEADERS | wire::H2_END_STREAM, b"\x00\x03x-a\x01b") ]
            }
            else {
                vec![ frame ]
            }
        });
        assert_eq!(body_of(response.clone()).unwrap(), wire::h2_body(&response));
    }

    #[test]
    fn padding_and_priority_are_removed() {
        let padded = wire::map_h2_frames(&fixtures::h2_response("doh2-google"), |mut frame| {
            if frame.kind == wire::H2_HEADERS {
                frame.flags |= wire::H2_PADDED | wire::H2_PRIORITY;
                frame.payload = [ &[ 3 ][..], &[ 0, 0, 0, 0, 16 ], &frame.payload, &[ 0; 3 ] ].concat();
            }
            else if frame.kind == wire::H2_DATA {
                frame.flags |= wire::H2_PADDED;
                frame.payload = [ &[ 10 ][..], &frame.payload, &[ 0; 10 ] ].concat();
            }
            vec![ frame ]
        });
        assert_eq!(body_of(padded).unwrap(), wire::h2_body(&fixtures::h2_response("doh2-google")));
    }

    #[test]
    fn padding_longer_than_the_frame() {
        let response = google_with_before(wire::H2_SETTINGS, frame_on(1, wire::H2_HEADERS, wire::H2_PADDED, &[ 200, 0x88 ]));
        assert_eq!(malformed(response), "A frame is too short for the padding or priority its flags say it has");
        assert_eq!(malformed(google_with_before(wire::H2_SETTINGS, frame_on(1, wire::H2_HEADERS, wire::H2_PADDED, &[]))),
                   "A frame is too short for the padding or priority its flags say it has");
        assert_eq!(malformed(google_with_before(wire::H2_SETTINGS, frame_on(1, wire::H2_HEADERS, wire::H2_PRIORITY, &[ 0, 0 ]))),
                   "A frame is too short for the padding or priority its flags say it has");
    }

    #[test]
    fn pings_are_answered() {
        let ping = frame_on(0, wire::H2_PING, 0, b"8 bytes!");
        let (body, sent) = read(google_with_before(wire::H2_HEADERS, ping));
        assert!(body.is_ok());
        assert_eq!(sent, [ settings_ack(), frame_on(0, wire::H2_PING, wire::H2_ACK, b"8 bytes!") ]);

        let acknowledgement = frame_on(0, wire::H2_PING, wire::H2_ACK, b"8 bytes!");
        assert_eq!(read(google_with_before(wire::H2_HEADERS, acknowledgement)).1, [ settings_ack() ]);
    }

    #[test]
    fn frames_dog_has_no_use_for_are_ignored() {
        assert!(body_of(google_with_before(wire::H2_HEADERS, frame_on(0, 0xfa, 0, b"from the future"))).is_ok());
        assert!(body_of(google_with_before(wire::H2_HEADERS, frame_on(3, wire::H2_DATA, wire::H2_END_STREAM, b"another stream"))).is_ok());
        assert!(body_of(google_with_before(wire::H2_HEADERS, frame_on(3, wire::H2_RST_STREAM, 0, &[ 0, 0, 0, 8 ]))).is_ok());
    }

    #[test]
    fn a_server_that_gives_up() {
        let goaway = |payload: &[u8]| malformed(google_with_before(wire::H2_HEADERS, frame_on(0, wire::H2_GOAWAY, 0, payload)));
        assert_eq!(goaway(&[ 0, 0, 0, 0, 0, 0, 0, 1 ]), "The server closed the connection (HTTP/2 error PROTOCOL_ERROR)");
        assert_eq!(goaway(&[ 0, 0, 0, 1, 0, 0, 0, 0x42, b'!' ]), "The server closed the connection (HTTP/2 error code 0x42)");
        assert_eq!(goaway(&[ 0, 0, 0, 0 ]), "The server closed the connection");

        let reset = frame_on(1, wire::H2_RST_STREAM, 0, &[ 0, 0, 0, 7 ]);
        assert_eq!(malformed(google_with_before(wire::H2_HEADERS, reset)), "The server cancelled the request (HTTP/2 error REFUSED_STREAM)");
    }

    #[test]
    fn a_pushed_response() {
        let push = frame_on(1, wire::H2_PUSH_PROMISE, wire::H2_END_HEADERS, &[ 0, 0, 0, 2, 0x82 ]);
        assert_eq!(malformed(google_with_before(wire::H2_HEADERS, push)), "The server pushed a response after being told not to");
    }

    #[test]
    fn a_body_before_its_headers() {
        let body = frame_on(1, wire::H2_DATA, 0, b"\x12\x34");
        assert_eq!(malformed(google_with_before(wire::H2_HEADERS, body)), "The response body came before its headers");
    }

    #[test]
    fn a_body_too_long_for_a_dns_message() {
        let mut response = fixtures::h2_response("doh2-google");
        for _ in 0 .. 4 {
            response = with_before(&response, wire::H2_DATA, frame_on(1, wire::H2_DATA, 0, &[ 0; 16_384 ]));
        }
        assert_eq!(malformed(response), "The response body is too long (more than 65535 bytes)");
    }

    #[test]
    fn a_frame_too_large() {
        let response = [ &[ 0x00, 0x40, 0x01, wire::H2_DATA, 0, 0, 0, 0, 1 ][..], &fixtures::h2_response("doh2-google") ].concat();
        assert_eq!(malformed(response), "The server sent a frame of 16385 bytes, more than the 16384 allowed");
    }

    #[test]
    fn responses_cut_short() {
        let response = fixtures::h2_response("doh2-quad9");
        for len in [ 0, 5, 9, 20, response.len() - 1 ] {
            assert!(matches!(body_of(response[.. len].to_vec()), Err(Error::TruncatedResponse)), "{len}");
        }
    }

    #[test]
    fn an_answer_that_cannot_be_sent() {
        let mut stream = duplex(fixtures::h2_response("doh2-google"));
        stream.writable = false;
        assert!(matches!(read_body(&mut stream, SHORT), Err(Error::NetworkError(_))));
        assert!(matches!(exchange(&mut stream, &url("dns.google"), &a_example(), SHORT), Err(Error::NetworkError(_))));
        stream.flush().unwrap();
    }

    // ---- whole exchanges ----

    fn exchange_with(mode: Http2) -> (Result<Response, Error>, Vec<Vec<u8>>) {
        let server = mock::http2(mode);
        let mut stream = net::connect_tcp("127.0.0.1", server.port(), Deadline::after(SHORT * 10)).unwrap();
        let result = exchange(&mut stream, &url("127.0.0.1"), &a_example(), SHORT);
        (result, server.requests())
    }

    #[test]
    fn exchange_over_plain_tcp() {
        let (result, requests) = exchange_with(Http2::Reply(fixtures::h2_response("doh2-quad9")));
        assert_eq!(result.unwrap().answers.len(), 1);
        assert!(requests[0].starts_with(PREFACE));
        assert_eq!(wire::h2_body(&requests[0]), a_example().to_bytes().unwrap());
    }

    #[test]
    fn an_answer_to_a_different_query_is_refused() {
        let (result, _) = exchange_with(Http2::Raw(fixtures::h2_response("doh2-cloudflare")));
        assert!(matches!(result, Err(Error::MismatchedResponse(dns::Mismatch::TransactionId { .. }))), "{result:?}");
    }
}
