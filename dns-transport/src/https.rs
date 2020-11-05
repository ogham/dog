#![cfg_attr(not(feature="https"), allow(unused))]

use std::io::{Read, Write};
use std::net::TcpStream;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **HTTPS transport**, which uses Hyper.
///
/// # Examples
///
/// ```no_run
/// use dns_transport::{Transport, HttpsTransport};
/// use dns::{Request, Flags, Query, Labels, QClass, qtype, record::A};
///
/// let query = Query {
///     qname: Labels::encode("dns.lookup.dog").unwrap(),
///     qclass: QClass::IN,
///     qtype: qtype!(A),
/// };
///
/// let request = Request {
///     transaction_id: 0xABCD,
///     flags: Flags::query(),
///     query: query,
///     additional: None,
/// };
///
/// let transport = HttpsTransport::new("https://cloudflare-dns.com/dns-query");
/// transport.send(&request);
/// ```
#[derive(Debug)]
pub struct HttpsTransport {
    url: String,
}

impl HttpsTransport {

    /// Creates a new HTTPS transport that connects to the given URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

impl Transport for HttpsTransport {

    #[cfg(feature="https")]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let connector = native_tls::TlsConnector::new()?;

        let (domain, path) = self.split_domain().expect("Invalid HTTPS nameserver");

        info!("Opening TLS socket to {:?}", domain);
        let stream = TcpStream::connect(format!("{}:443", domain))?;
        let mut stream = connector.connect(domain, stream)?;

        let request_bytes = request.to_bytes().expect("failed to serialise request");
        let mut bytes = format!("\
            POST {} HTTP/1.1\r\n\
            Host: {}\r\n\
            Content-Type: application/dns-message\r\n\
            Accept: application/dns-message\r\n\
            User-Agent: {}\r\n\
            Content-Length: {}\r\n\r\n",
            path, domain, USER_AGENT, request_bytes.len()).into_bytes();
        bytes.extend(request_bytes);

        info!("Sending {:?} bytes of data to {}", bytes.len(), self.url);
        stream.write_all(&bytes)?;
        debug!("Sent");

        info!("Waiting to receive...");
        let mut buf = [0; 4096];
        let read_len = stream.read(&mut buf)?;
        info!("Received {} bytes of data", read_len);

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut response = httparse::Response::new(&mut headers);
        let index: usize = response.parse(&buf).unwrap().unwrap();
        let body = &buf[index .. read_len];

        if response.code != Some(200) {
            return Err(Error::BadRequest);
        }

        for header in response.headers {
            trace!("Header {:?} -> {:?}", header.name, String::from_utf8_lossy(header.value));
        }

        info!("HTTP body has {} bytes", body.len());
        let response = Response::from_bytes(&body)?;
        Ok(response)
    }

    #[cfg(not(feature="https"))]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        unimplemented!("HTTPS feature disabled")
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

