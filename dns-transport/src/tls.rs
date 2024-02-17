#![cfg_attr(not(feature = "tls"), allow(unused))]

use std::net::TcpStream;
use std::io::Write;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error, TcpTransport};
use super::tls_stream::TlsStream;


/// The **TLS transport**, which sends DNS wire data using TCP through an
/// encrypted TLS connection.
pub struct TlsTransport {
    addr: String,
    custom_port: u16
}

impl TlsTransport {

    /// Creates a new TLS transport that connects to the given host.
    pub fn new(addr: String, port: Option<u16>) -> Self {
        let custom_port: u16 = match port {
            Some(p) => p,
            None => 853,
        };
        Self { addr, custom_port }
    }
}



impl Transport for TlsTransport {

    #[cfg(feature = "with_tls")]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        use native_tls::TlsStream;

        info!("Opening TLS socket");

        let domain = self.sni_domain();
        info!("Connecting using domain {:?}", domain);
        // comminicate that the port must EXPLICATLY BE SEPERATE
        let mut stream: TlsStream<TcpStream> = Self::stream(&self.addr, *&self.custom_port)?;

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

    #[cfg(not(feature = "with_tls"))]
    fn send(&self, request: &Request) -> Result<Response, Error> {
        unreachable!("TLS feature disabled")
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
