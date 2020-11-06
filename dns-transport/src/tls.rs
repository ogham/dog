#![cfg_attr(not(feature="tls"), allow(unused))]

use std::net::TcpStream;
use std::io::Write;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error, TcpTransport};


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

        let domain = self.sni_domain();
        info!("Connecting using domain {:?}", domain);
        let mut stream = connector.connect(domain, stream).unwrap();
        debug!("Connected");

        // The message is prepended with the length when sent over TCP,
        // so the server knows how long it is (RFC 1035 §4.2.2)
        let mut bytes_to_send = request.to_bytes().expect("failed to serialise request");
        TcpTransport::prefix_with_length(&mut bytes_to_send);

        info!("Sending {} bytes of data to {} over TLS", bytes_to_send.len(), self.addr);
        stream.write_all(&bytes_to_send)?;
        debug!("Wrote all bytes");

        let read_bytes = TcpTransport::length_prefixed_read(&mut stream)?;
        let response = Response::from_bytes(&read_bytes)?;
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
