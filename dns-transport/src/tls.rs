use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error, DEFAULT_TIMEOUT};
use super::{address, tcp, tls_stream};
use super::net::Deadline;


/// The **TLS transport**, which sends DNS wire data using TCP through an
/// encrypted TLS connection (DNS-over-TLS).
///
/// # References
///
/// - [RFC 7858](https://tools.ietf.org/html/rfc7858) — Specification for
///   DNS over Transport Layer Security (May 2016)
pub struct TlsTransport {
    addr: String,
    timeout: Duration,
}

impl TlsTransport {

    /// Creates a new TLS transport that connects to the given host, and
    /// waits for it for the default time.
    pub fn new(addr: String) -> Self {
        Self::with_timeout(addr, DEFAULT_TIMEOUT)
    }

    /// Creates a new TLS transport that connects to the given host, and
    /// gives up if the whole exchange has not finished within `timeout`.
    pub fn with_timeout(addr: String, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}


impl Transport for TlsTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let deadline = Deadline::after(self.timeout);

        info!("Opening TLS socket");
        let (host, port) = address::parse_host_port(&self.addr, 853)?;

        info!("Connecting using domain {host:?}");
        let mut stream = tls_stream::connect(host, port, deadline, &[])?;
        debug!("Connected");

        info!("Sending a request to {:?} over TLS", self.addr);
        tcp::exchange(&mut stream, request, self.timeout)
    }
}
