use log::*;

use std::time::Duration;

use dns::{Request, Response};
use super::{Transport, Error, UdpTransport, TcpTransport};


/// The **automatic transport**, which sends DNS wire data using the UDP
/// transport, then tries using the TCP transport if the first one fails
/// because the response wouldn’t fit in a single UDP packet.
///
/// This is the default behaviour for many DNS clients.
pub struct AutoTransport {
    addr: String,
}

impl AutoTransport {

    /// Creates a new automatic transport that connects to the given host.
    pub fn new(addr: String) -> Self {
        Self { addr }
    }
}


impl Transport for AutoTransport {
    fn send(&self, request: &Request, timeout: Option<Duration>) -> Result<Response, Error> {
        let udp_transport = UdpTransport::new(self.addr.clone());
        let udp_response = udp_transport.send(&request, timeout)?;

        if ! udp_response.flags.truncated {
            return Ok(udp_response);
        }

        debug!("Truncated flag set, so switching to TCP");

        let tcp_transport = TcpTransport::new(self.addr.clone());
        let tcp_response = tcp_transport.send(&request, timeout)?;
        Ok(tcp_response)
    }
}
