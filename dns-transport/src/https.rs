#![cfg_attr(not(feature = "https"), allow(unused))]

use std::io::{Read, Write};
use std::net::TcpStream;

use log::*;

use dns::{Request, Response, WireError};
use super::{Transport, Error};

use super::tls_stream;

/// The **HTTPS transport**, which sends DNS wire data inside HTTP packets
/// encrypted with TLS, using TCP.
pub struct HttpsTransport {
    url: String,
}

impl HttpsTransport {

    /// Creates a new HTTPS transport that connects to the given URL.
    pub fn new(url: String) -> Self {
        Self { url }
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn contains_header(buf: &[u8]) -> bool {
    let header_end: [u8; 4] = [ 13, 10, 13, 10 ];
    find_subsequence(buf, &header_end).is_some()
}

use tls_stream::TlsStream;

impl Transport for HttpsTransport {

    #[cfg(any(feature = "with_https"))]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let (domain, path) = self.split_domain().expect("Invalid HTTPS nameserver");

        info!("Opening TLS socket to {:?}", domain);
        let mut stream = Self::stream(&domain, 443)?;

        debug!("Connected");

        let request_bytes = request.to_bytes().expect("failed to serialise request");
        let mut bytes_to_send = format!("\
            POST {} HTTP/1.1\r\n\
            Host: {}\r\n\
            Content-Type: application/dns-message\r\n\
            Accept: application/dns-message\r\n\
            User-Agent: {}\r\n\
            Content-Length: {}\r\n\r\n",
            path, domain, USER_AGENT, request_bytes.len()).into_bytes();
        bytes_to_send.extend(request_bytes);

        info!("Sending {} bytes of data to {:?} over HTTPS", bytes_to_send.len(), self.url);
        stream.write_all(&bytes_to_send)?;
        debug!("Wrote all bytes");

        info!("Waiting to receive...");
        let mut buf = [0; 4096];
        let mut read_len = stream.read(&mut buf)?;
        while !contains_header(&buf[0..read_len]) {
            if read_len == buf.len() {
                return Err(Error::WireError(WireError::IO));
            }
            read_len += stream.read(&mut buf[read_len..])?;
        }
        let mut expected_len = read_len;
        info!("Received {} bytes of data", read_len);

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut response = httparse::Response::new(&mut headers);
        let index: usize = response.parse(&buf)?.unwrap();

        if response.code != Some(200) {
            let reason = response.reason.map(str::to_owned);
            return Err(Error::WrongHttpStatus(response.code.unwrap(), reason));
        }

        for header in response.headers {
            let str_value = String::from_utf8_lossy(header.value);
            debug!("Header {:?} -> {:?}", header.name, str_value);
            if header.name == "Content-Length" {
                let content_length: usize = str_value.parse().unwrap();
                expected_len = index + content_length;
            }
        }

        while read_len < expected_len {
            if read_len == buf.len() {
                return Err(Error::WireError(WireError::IO));
            }
            read_len += stream.read(&mut buf[read_len..])?;
        }

        let body = &buf[index .. read_len];
        debug!("HTTP body has {} bytes", body.len());
        let response = Response::from_bytes(&body)?;
        Ok(response)
    }

    #[cfg(not(feature = "with_https"))]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        unreachable!("HTTPS feature disabled")
    }
}

impl HttpsTransport {
    fn split_domain(&self) -> Option<(&str, &str)> {
        if let Some(sp) = self.url.strip_prefix("https://") {
            if let Some(colon_index) = sp.find('/') {
                return Some((&sp[.. colon_index], &sp[colon_index ..]));
            }
        }

        None
    }
}

/// The User-Agent header sent with HTTPS requests.
static USER_AGENT: &str = concat!("dog/", env!("CARGO_PKG_VERSION"));

