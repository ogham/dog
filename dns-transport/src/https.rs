#![cfg_attr(not(feature = "https"), allow(unused))]

use std::io::{Read, Write};
use std::net::TcpStream;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};


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

impl Transport for HttpsTransport {

    #[cfg(feature = "with_https")]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let connector = native_tls::TlsConnector::new()?;

        let (domain, path) = self.split_domain().expect("Invalid HTTPS nameserver");

        info!("Opening TLS socket to {:?}", domain);
        let stream = TcpStream::connect(format!("{}:443", domain))?;
        let mut stream = connector.connect(domain, stream)?;
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
        let read_len = stream.read(&mut buf)?;
        info!("Received {} bytes of data", read_len);

        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut response = httparse::Response::new(&mut headers);
        let index: usize = response.parse(&buf)?.unwrap();
        let body = &buf[index .. read_len];

        if response.code != Some(200) {
            let reason = response.reason.map(str::to_owned);
            return Err(Error::WrongHttpStatus(response.code.unwrap(), reason));
        }

        for header in response.headers {
            debug!("Header {:?} -> {:?}", header.name, String::from_utf8_lossy(header.value));
        }

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

