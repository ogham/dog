#![cfg_attr(not(feature="tls"), allow(unused))]

use std::convert::TryFrom;
use std::net::TcpStream;
use std::io::{Read, Write};

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **TLS transport**, which sends DNS wire data using TCP through an
/// encrypted TLS connection.
///
/// # Examples
///
/// ```no_run
/// use dns_transport::{Transport, TlsTransport};
/// use dns::{Request, Flags, Query, Labels, QClass, qtype, record::SRV};
///
/// let query = Query {
///     qname: Labels::encode("dns.lookup.dog").unwrap(),
///     qclass: QClass::IN,
///     qtype: qtype!(SRV),
/// };
///
/// let request = Request {
///     transaction_id: 0xABCD,
///     flags: Flags::query(),
///     query: query,
///     additional: None,
/// };
///
/// let transport = TlsTransport::new("dns.google");
/// transport.send(&request);
/// ```
pub struct TlsTransport {
    addr: String,
}

impl TlsTransport {

    /// Creates a new TLS transport that connects to the given host.
    pub fn new(sa: impl Into<String>) -> Self {
        let addr = sa.into();
        Self { addr }
    }
}

impl Transport for TlsTransport {

    #[cfg(feature="tls")]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let connector = native_tls::TlsConnector::new()?;

        info!("Opening TLS socket");
        let stream =
            if self.addr.contains(':') {
                TcpStream::connect(&*self.addr)?
            }
            else {
                TcpStream::connect((&*self.addr, 853))?
            };

        info!("Connecting");
        let mut stream = connector.connect(self.sni_domain(), stream).unwrap();

        // As with TCP, we need to prepend the message with its length.
        let mut bytes = request.to_bytes().expect("failed to serialise request");
        let len_bytes = u16::try_from(bytes.len()).expect("request too long").to_be_bytes();
        bytes.insert(0, len_bytes[0]);
        bytes.insert(1, len_bytes[1]);

        info!("Sending {} bytes of data to {}", bytes.len(), self.addr);
        stream.write_all(&bytes)?;
        debug!("Sent");

        info!("Waiting to receive...");
        let mut buf = [0; 4096];
        let read_len = stream.read(&mut buf)?;

        // Remember to deal with the length again.
        info!("Received {} bytes of data", read_len);
        let response = Response::from_bytes(&buf[2 .. read_len])?;

        Ok(response)
    }

    #[cfg(not(feature="tls"))]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        unimplemented!("TLS feature disabled")
    }
}

impl TlsTransport {
    fn sni_domain(&self) -> &str {
        if let Some(colon_index) = self.addr.find(':') {
            &self.addr[.. colon_index]
        }
        else {
            &self.addr[..]
        }
    }
}
