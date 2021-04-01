use std::net::{Ipv4Addr, UdpSocket};

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **UDP transport**, which sends DNS wire data inside a UDP datagram.
///
/// # References
///
/// - [RFC 1035 §4.2.1](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
pub struct UdpTransport {
    addr: String,
}

impl UdpTransport {

    /// Creates a new UDP transport that connects to the given host.
    pub fn new(addr: String) -> Self {
        Self { addr }
    }
}


impl Transport for UdpTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        info!("Opening UDP socket");
        // TODO: This will need to be changed for IPv6 support.
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;

        if self.addr.contains(':') {
            socket.connect(&*self.addr)?;
        }
        else {
            socket.connect((&*self.addr, 53))?;
        }
        debug!("Opened");

        let bytes_to_send = request.to_bytes().expect("failed to serialise request");

        info!("Sending {} bytes of data to {} over UDP", bytes_to_send.len(), self.addr);
        let written_len = socket.send(&bytes_to_send)?;
        debug!("Wrote {} bytes", written_len);

        info!("Waiting to receive...");
        let mut buf = vec![0; 4096];
        let received_len = socket.recv(&mut buf)?;

        info!("Received {} bytes of data", received_len);
        let response = Response::from_bytes(&buf[.. received_len])?;
        Ok(response)
    }
}
