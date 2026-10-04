use std::io::{self, Read, Write};
use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error, DEFAULT_TIMEOUT};
use super::address::{self, HttpsUrl};
use super::{h2, net, tls_stream};
use super::net::Deadline;


/// The most of an HTTP response’s head that dog will read.
const MAX_HEAD: usize = 8 * 1024;

/// The longest body dog will read: the longest a DNS message can be.
pub(crate) const MAX_BODY: usize = 65_535;

/// The User-Agent header sent with HTTPS requests.
pub(crate) static USER_AGENT: &str = concat!("dog/", env!("CARGO_PKG_VERSION"));


/// The **HTTPS transport**, which sends DNS wire data inside HTTP packets
/// encrypted with TLS, using TCP (DNS-over-HTTPS).
///
/// # References
///
/// - [RFC 8484](https://tools.ietf.org/html/rfc8484) — DNS Queries over
///   HTTPS (October 2018)
pub struct HttpsTransport {
    url: String,
    timeout: Duration,
}

impl HttpsTransport {

    /// Creates a new HTTPS transport that connects to the given URL, and
    /// waits for it for the default time.
    pub fn new(url: String) -> Self {
        Self::with_timeout(url, DEFAULT_TIMEOUT)
    }

    /// Creates a new HTTPS transport that connects to the given URL, and
    /// gives up if the whole exchange has not finished within `timeout`.
    pub fn with_timeout(url: String, timeout: Duration) -> Self {
        Self { url, timeout }
    }
}

impl Transport for HttpsTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let deadline = Deadline::after(self.timeout);
        let url = address::parse_https_url(&self.url)?;

        info!("Opening TLS socket to {:?}", url.host);
        let mut stream = tls_stream::connect(url.host, url.port, deadline, &[ "h2", "http/1.1" ])?;
        debug!("Connected");

        if speaks_http2(&stream) {
            info!("The server chose HTTP/2");
            h2::exchange(&mut stream, &url, request, self.timeout)
        }
        else {
            exchange_https(&mut stream, &url, request, self.timeout)
        }
    }
}

/// Whether the server chose HTTP/2 when the connection was made (ALPN, RFC
/// 7301). A server that chose nothing gets HTTP/1.1.
fn speaks_http2(stream: &tls_stream::Stream) -> bool {
    stream.negotiated_alpn()
        .inspect_err(|e| warn!("Could not tell which protocol the server chose: {e}"))
        .ok().flatten().as_deref() == Some(b"h2")
}


/// Sends a request as an HTTP POST and reads the answer from the response
/// body. Returns an error if it does not answer the request.
pub(crate) fn exchange_https(stream: &mut (impl Read + Write), url: &HttpsUrl<'_>, request: &Request, timeout: Duration) -> Result<Response, Error> {
    let bytes_to_send = build_http_request(url, &request.to_bytes()?);
    info!("Sending {} bytes of data to {}:{} over HTTPS", bytes_to_send.len(), url.host, url.port);
    stream.write_all(&bytes_to_send).and_then(|()| stream.flush()).map_err(|e| net::io_error(e, timeout))?;
    debug!("Wrote all bytes");

    let body = read_http_body(stream, timeout)?;
    debug!("HTTP body has {} bytes", body.len());

    let response = Response::from_bytes(&body)?;
    request.check_response(&response)?;
    Ok(response)
}

/// The HTTP request that carries a DNS message (RFC 8484 §4.1).
pub(crate) fn build_http_request(url: &HttpsUrl<'_>, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!("\
        POST {} HTTP/1.1\r\n\
        Host: {}\r\n\
        Content-Type: application/dns-message\r\n\
        Accept: application/dns-message\r\n\
        User-Agent: {}\r\n\
        Content-Length: {}\r\n\r\n",
        url.path, host_header(url), USER_AGENT, body.len()).into_bytes();

    bytes.extend_from_slice(body);
    bytes
}

/// The value of the Host header: the host, in brackets if it is an IPv6
/// address, and its port if that isn’t the default (RFC 9110 §7.2).
pub(crate) fn host_header(url: &HttpsUrl<'_>) -> String {
    let host = if url.host.contains(':') { format!("[{}]", url.host) } else { url.host.to_owned() };
    if url.port == 443 { host } else { format!("{host}:{}", url.port) }
}


/// Reads an HTTP response and returns its body, which should be a whole DNS
/// message: the status must be 200 OK, and the body must come in one piece,
/// with its length given.
pub(crate) fn read_http_body(stream: &mut impl Read, timeout: Duration) -> Result<Vec<u8>, Error> {
    info!("Waiting to receive...");
    let mut data = Vec::new();
    let head_end = read_head(stream, &mut data, timeout)?;
    let body_end = head_end + parse_head(&data[.. head_end])?;

    while data.len() < body_end {
        read_more(stream, &mut data, timeout)?;
    }

    data.truncate(body_end);
    Ok(data.split_off(head_end))
}

/// Reads until the blank line that ends the head of the response, and
/// returns where the head ends. Anything after it stays in `data` as the
/// start of the body.
fn read_head(stream: &mut impl Read, data: &mut Vec<u8>, timeout: Duration) -> Result<usize, Error> {
    loop {
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok(end + 4);
        }

        if data.len() > MAX_HEAD {
            return Err(Error::MalformedHttp(format!("The response headers are longer than {MAX_HEAD} bytes")));
        }

        read_more(stream, data, timeout)?;
    }
}

/// Reads whatever the stream has next onto the end of `data`. The stream
/// ending here means the response was cut short.
fn read_more(stream: &mut impl Read, data: &mut Vec<u8>, timeout: Duration) -> Result<(), Error> {
    let mut buf = [0; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Err(Error::TruncatedResponse),
            Ok(read) => {
                data.extend_from_slice(&buf[.. read]);
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(net::io_error(e, timeout)),
        }
    }
}

/// Checks the head of an HTTP response, and returns the length of its body.
pub(crate) fn parse_head(head: &[u8]) -> Result<usize, Error> {
    let mut headers = [ httparse::EMPTY_HEADER; 64 ];
    let mut response = httparse::Response::new(&mut headers);
    if response.parse(head)?.is_partial() {
        return Err(Error::MalformedHttp("The response headers are incomplete".into()));
    }

    if response.code != Some(200) {
        let reason = response.reason.map(str::to_owned);
        return Err(Error::WrongHttpStatus(response.code.unwrap_or_default(), reason));
    }

    content_length(response.headers)
}

/// The body length a response declares, which must be a number no bigger
/// than a DNS message can be. Bodies sent in chunks are not supported.
fn content_length(headers: &[httparse::Header<'_>]) -> Result<usize, Error> {
    if let Some(encoding) = header(headers, "Transfer-Encoding") {
        return Err(Error::MalformedHttp(format!("Responses with Transfer-Encoding {:?} are not supported", String::from_utf8_lossy(encoding))));
    }

    let value = header(headers, "Content-Length")
        .ok_or_else(|| Error::MalformedHttp("The response has no Content-Length".into()))?;

    let length = std::str::from_utf8(value).ok()
        .and_then(|text| text.trim().parse::<usize>().ok())
        .ok_or_else(|| Error::MalformedHttp(format!("Invalid Content-Length {:?}", String::from_utf8_lossy(value))))?;

    if length > MAX_BODY {
        return Err(Error::MalformedHttp(format!("The response body is too long ({length} bytes)")));
    }

    Ok(length)
}

/// The value of a header, whatever the case of its name.
fn header<'a>(headers: &[httparse::Header<'a>], name: &str) -> Option<&'a [u8]> {
    headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
}


#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use std::time::Instant;
    use crate::test_util::{a_example, SHORT};
    use test_support::{fixtures, mock::{self, Http}, wire};

    fn body_of(response: &[u8]) -> Result<Vec<u8>, Error> {
        read_http_body(&mut Cursor::new(response.to_vec()), SHORT)
    }

    fn status(response: &[u8]) -> (u16, Option<String>) {
        match body_of(response) { Err(Error::WrongHttpStatus(code, reason)) => (code, reason), other => panic!("expected a wrong status, got {other:?}") }
    }

    fn malformed(response: &[u8]) -> String {
        match body_of(response) { Err(Error::MalformedHttp(why)) => why, other => panic!("expected malformed HTTP, got {other:?}") }
    }

    /// A real response with its Content-Length header changed.
    fn with_content_length(value: &str) -> Vec<u8> {
        wire::map_http_headers(&fixtures::http_response("doh-cloudflare"), |line| {
            if line.to_ascii_lowercase().starts_with("content-length:") { Some(format!("Content-Length: {value}")) } else { Some(line.to_owned()) }
        })
    }

    #[test]
    fn real_answers() {
        for name in [ "doh-cloudflare", "doh-google" ] {
            let response = fixtures::http_response(name);
            assert_eq!(body_of(&response).unwrap(), wire::http_body(&response), "{name}");
        }
    }

    #[test]
    fn real_error_statuses() {
        assert_eq!(status(&fixtures::http_response("doh-google-404")), (404, Some("Not Found".into())));
        assert_eq!(status(&fixtures::http_response("doh-google-400")), (400, Some("Bad Request".into())));
        assert_eq!(status(&fixtures::http_response("doh-httpbin-500")), (500, Some("INTERNAL SERVER ERROR".into())));
    }

    #[test]
    fn a_real_empty_body() {
        assert_eq!(body_of(&fixtures::http_response("doh-httpbin-200")).unwrap(), b"");
    }

    #[test]
    fn header_names_in_any_case() {
        let lowered = wire::map_http_headers(&fixtures::http_response("doh-google"), |line| Some(line.to_ascii_lowercase()));
        assert_eq!(body_of(&lowered).unwrap(), wire::http_body(&lowered));
    }

    #[test]
    fn content_length_must_be_a_small_number() {
        assert_eq!(malformed(&with_content_length("sixty-five")), r#"Invalid Content-Length "sixty-five""#);
        assert_eq!(malformed(&with_content_length("99999999999999999999")), r#"Invalid Content-Length "99999999999999999999""#);
        assert_eq!(malformed(&with_content_length("-1")), r#"Invalid Content-Length "-1""#);
        assert_eq!(malformed(&with_content_length("70000")), "The response body is too long (70000 bytes)");
    }

    #[test]
    fn content_length_is_required() {
        let without = wire::map_http_headers(&fixtures::http_response("doh-cloudflare"), |line| {
            (!line.to_ascii_lowercase().starts_with("content-length:")).then(|| line.to_owned())
        });
        assert_eq!(malformed(&without), "The response has no Content-Length");
    }

    #[test]
    fn chunked_bodies_are_not_supported() {
        let chunked = wire::map_http_headers(&fixtures::http_response("doh-cloudflare"), |line| {
            if line.to_ascii_lowercase().starts_with("content-length:") { Some("Transfer-Encoding: chunked".into()) } else { Some(line.to_owned()) }
        });
        assert_eq!(malformed(&chunked), r#"Responses with Transfer-Encoding "chunked" are not supported"#);
    }

    /// Real servers send a dozen headers; dog makes room for many more.
    #[test]
    fn many_headers() {
        let response = fixtures::http_response("doh-google");
        let mut lines = wire::http_head_lines(&response);
        lines.extend((0 .. 40).map(|n| format!("X-Filler-{n}: yes")));
        let padded = wire::http_message(&lines, wire::http_body(&response));
        assert_eq!(body_of(&padded).unwrap(), wire::http_body(&response));

        lines.extend((40 .. 80).map(|n| format!("X-Filler-{n}: yes")));
        let too_many = wire::http_message(&lines, wire::http_body(&response));
        assert!(matches!(body_of(&too_many), Err(Error::HttpError(httparse::Error::TooManyHeaders))));
    }

    #[test]
    fn endless_headers() {
        let endless = [ &b"HTTP/1.1 200 OK\r\nX-Endless: "[..], &[ b'x'; 9000 ] ].concat();
        assert_eq!(malformed(&endless), "The response headers are longer than 8192 bytes");
    }

    #[test]
    fn headers_that_are_not_http() {
        assert!(matches!(body_of(b"SSH-2.0-OpenSSH\r\n\r\n"), Err(Error::HttpError(_))));
    }

    #[test]
    fn an_incomplete_head() {
        assert!(matches!(parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n"), Err(Error::MalformedHttp(_))));
    }

    #[test]
    fn responses_cut_short() {
        let response = fixtures::http_response("doh-cloudflare");
        let head_end = wire::http_header_end(&response).unwrap();
        for len in [ 0, head_end / 2, head_end + 1, response.len() - 1 ] {
            assert!(matches!(body_of(&response[.. len]), Err(Error::TruncatedResponse)), "{len}");
        }
    }

    #[test]
    fn bytes_after_the_body_are_ignored() {
        let response = fixtures::http_response("doh-cloudflare");
        let extended = [ &response[..], b"HTTP/1.1 200 OK\r\n" ].concat();
        assert_eq!(body_of(&extended).unwrap(), wire::http_body(&response));
    }

    /// A reader that is interrupted once before each successful read.
    struct Interrupting { data: Cursor<Vec<u8>>, interrupt: bool }

    impl Read for Interrupting {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.interrupt = !self.interrupt;
            if self.interrupt { Err(io::ErrorKind::Interrupted.into()) } else { self.data.read(buf) }
        }
    }

    #[test]
    fn interrupted_reads_are_retried() {
        let response = fixtures::http_response("doh-google");
        let mut reader = Interrupting { data: Cursor::new(response.clone()), interrupt: false };
        assert_eq!(read_http_body(&mut reader, SHORT).unwrap(), wire::http_body(&response));
    }

    struct Failing(io::ErrorKind);

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(self.0.into())
        }
    }

    #[test]
    fn read_failures() {
        assert!(matches!(read_http_body(&mut Failing(io::ErrorKind::WouldBlock), SHORT), Err(Error::Timeout(SHORT))));
        assert!(matches!(read_http_body(&mut Failing(io::ErrorKind::ConnectionReset), SHORT), Err(Error::NetworkError(_))));
    }

    /// The request is byte for byte the one dog has always sent, which is
    /// what the capture script sent to Cloudflare.
    #[test]
    fn the_request_matches_what_was_captured() {
        let captured = fixtures::http_request("doh-cloudflare");
        let url = HttpsUrl { host: "cloudflare-dns.com", port: 443, path: "/dns-query" };
        assert_eq!(build_http_request(&url, wire::http_body(&captured)), captured);
    }

    #[test]
    fn host_headers() {
        let host = |host, port| host_header(&HttpsUrl { host, port, path: "/" });
        assert_eq!(host("dns.google", 443), "dns.google");
        assert_eq!(host("localhost", 8443), "localhost:8443");
        assert_eq!(host("::1", 443), "[::1]");
        assert_eq!(host("::1", 8443), "[::1]:8443");
    }

    fn exchange_within(mode: Http, deadline: Deadline) -> (Result<Response, Error>, Vec<Vec<u8>>) {
        let server = mock::http(mode);
        let mut stream = net::connect_tcp("127.0.0.1", server.port(), deadline).unwrap();
        let url = HttpsUrl { host: "127.0.0.1", port: server.port(), path: "/dns-query" };
        let result = exchange_https(&mut stream, &url, &a_example(), SHORT);
        (result, server.requests())
    }

    fn exchange_with(mode: Http) -> (Result<Response, Error>, Vec<Vec<u8>>) {
        exchange_within(mode, Deadline::after(SHORT * 10))
    }

    /// A server that sent its response a byte at a time, each well within
    /// the timeout, used to hold dog for as long as it kept sending.
    #[test]
    fn a_response_trickled_out_a_byte_at_a_time() {
        let started = Instant::now();
        let (result, _) = exchange_within(Http::Trickle(fixtures::http_response("doh-google"), SHORT / 3), Deadline::after(SHORT));
        assert!(matches!(result, Err(Error::Timeout(SHORT))), "{result:?}");
        assert!(started.elapsed() < SHORT * 3, "{:?}", started.elapsed());
    }

    #[test]
    fn exchange_over_plain_tcp() {
        let (result, requests) = exchange_with(Http::Reply(fixtures::http_response("doh-cloudflare")));
        assert_eq!(result.unwrap().answers.len(), 1);
        assert!(requests[0].starts_with(b"POST /dns-query HTTP/1.1\r\nHost: 127.0.0.1:"), "{:?}", String::from_utf8_lossy(&requests[0]));
    }

    #[test]
    fn exchange_with_a_response_arriving_byte_by_byte() {
        let (result, _) = exchange_with(Http::Drip(fixtures::http_response("doh-google")));
        assert_eq!(result.unwrap().answers.len(), 1);
    }

    #[test]
    fn an_answer_to_a_different_query_is_refused() {
        let (result, _) = exchange_with(Http::Raw(fixtures::http_response("doh-cloudflare")));
        assert!(matches!(result, Err(Error::MismatchedResponse(dns::Mismatch::TransactionId { .. }))), "{result:?}");
    }
}
