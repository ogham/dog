use async_trait::async_trait;
use log::*;

use dns::{Request, Response};
use super::{Transport, Error, UdpTransport, TcpTransport};


/// The **automatic transport**, which uses the UDP transport, then tries
/// using the TCP transport if the first one fails.
///
/// # Examples
///
/// ```no_run
/// use dns_transport::{Transport, AutoTransport};
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
///     query: query,
///     additional: None,
/// };
///
/// let transport = AutoTransport::new("8.8.8.8");
/// transport.send(&request);
/// ```
#[derive(Debug)]
pub struct AutoTransport {
    addr: String,
}

impl AutoTransport {

    /// Creates a new automatic transport that connects to the given host.
    pub fn new(sa: impl Into<String>) -> Self {
        let addr = sa.into();
        Self { addr }
    }
}


#[async_trait]
impl Transport for AutoTransport {
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        let udp_transport = UdpTransport::new(&self.addr);
        let udp_response = udp_transport.send(&request).await?;

        if ! udp_response.flags.truncated {
            return Ok(udp_response);
        }

        debug!("Truncated flag set, so switching to TCP");

        let tcp_transport = TcpTransport::new(&self.addr);
        let tcp_response = tcp_transport.send(&request).await?;
        Ok(tcp_response)
    }
}
