use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error, UdpTransport, TcpTransport, DEFAULT_TIMEOUT};


/// The **automatic transport**, which sends DNS wire data using the UDP
/// transport, then tries using the TCP transport if the first one fails
/// because the response wouldn’t fit in a single UDP packet.
///
/// This is the default behaviour for many DNS clients.
pub struct AutoTransport {
    addr: String,
    timeout: Duration,
}

impl AutoTransport {

    /// Creates a new automatic transport that connects to the given host,
    /// and waits for it for the default time.
    pub fn new(addr: String) -> Self {
        Self::with_timeout(addr, DEFAULT_TIMEOUT)
    }

    /// Creates a new automatic transport that connects to the given host,
    /// and waits at most `timeout` for each of its UDP and TCP exchanges.
    pub fn with_timeout(addr: String, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}


impl Transport for AutoTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let udp_transport = UdpTransport::with_timeout(self.addr.clone(), self.timeout);
        let udp_response = udp_transport.send(request)?;

        if ! udp_response.flags.truncated {
            return Ok(udp_response);
        }

        debug!("Truncated flag set, so switching to TCP");

        let tcp_transport = TcpTransport::with_timeout(self.addr.clone(), self.timeout);
        tcp_transport.send(request)
    }
}
