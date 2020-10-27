use async_trait::async_trait;
use log::*;
use native_tls::TlsConnector;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **TLS transport**, which uses Tokio.
///
/// # Examples
///
/// ```no_run
/// use dns_transport::{Transport, TlsTransport};
/// use dns::{Request, Flags, Query, QClass, qtype, record::SRV};
///
/// let query = Query {
///     qname: String::from("dns.lookup.dog"),
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
#[derive(Debug)]
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

#[async_trait]
impl Transport for TlsTransport {
    async fn send(&self, request: &Request) -> Result<Response, Error> {
        let connector = TlsConnector::new()?;
        let connector = tokio_tls::TlsConnector::from(connector);

        info!("Opening TLS socket");
        let stream =
            if self.addr.contains(':') {
                TcpStream::connect(&*self.addr).await?
            }
            else {
                TcpStream::connect((&*self.addr, 853)).await?
            };

        info!("Connecting");
        let mut stream = connector.connect(self.sni_domain(), stream).await?;

        // As with TCP, we need to prepend the message with its length.
        let mut bytes = request.to_bytes().expect("failed to serialise request");
        let len_bytes = (bytes.len() as u16).to_be_bytes();
        bytes.insert(0, len_bytes[0]);
        bytes.insert(1, len_bytes[1]);

        info!("Sending {} bytes of data to {}", bytes.len(), self.addr);

        stream.write_all(&bytes).await?;
        debug!("Sent");

        info!("Waiting to receive...");
        let mut buf = [0; 4096];
        let len = stream.read(&mut buf).await?;

        // Remember to deal with the length again.
        info!("Received {} bytes of data", buf.len());
        let response = Response::from_bytes(&buf[2..len])?;

        Ok(response)
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
