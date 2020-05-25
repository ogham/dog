use std::net::Ipv4Addr;

use async_trait::async_trait;
use log::*;
use tokio::net::UdpSocket;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **UDP transport**, which uses the stdlib.
///
/// # Examples
///
/// ```no_run
/// use dns_transport::{Transport, UdpTransport};
/// use dns::{Request, Flags, Query, QClass, qtype, record::NS};
///
/// let query = Query {
///     qname: String::from("dns.lookup.dog"),
///     qclass: QClass::IN,
///     qtype: qtype!(NS),
/// };
///
/// let request = Request {
///     transaction_id: 0xABCD,
///     flags: Flags::query(),
///     queries: vec![ query ],
///     additional: None,
/// };
///
/// let transport = UdpTransport::new("8.8.8.8");
/// transport.send(&request);
/// ```
#[derive(Debug)]
pub struct UdpTransport {
    addr: String,
}

impl UdpTransport {

    /// Creates a new UDP transport that connects to the given host.
    pub fn new(sa: impl Into<String>) -> Self {
        let addr = sa.into();
        Self { addr }
    }
}


#[async_trait]
impl Transport for UdpTransport {
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        info!("Opening UDP socket");
        let mut socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;

        if self.addr.contains(':') {
            socket.connect(&*self.addr).await?;
        }
        else {
            socket.connect((&*self.addr, 53)).await?;
        }

        let bytes = request.to_bytes().expect("failed to serialise request");
        info!("Sending {} bytes of data to {} over UDP", bytes.len(), self.addr);

        let len = socket.send(&bytes).await?;
        debug!("Sent {} bytes", len);

        info!("Waiting to receive...");
        let mut buf = vec![0; 1024];
        let len = socket.recv(&mut buf).await?;

        info!("Received {} bytes of data", len);
        let response = Response::from_bytes(&buf[..len])?;

        Ok(response)
    }
}
