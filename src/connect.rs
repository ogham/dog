//! Creating DNS transports based on the user’s input arguments.

use dns_transport::*;

use crate::resolve::Nameserver;


/// A **transport type** creates a `Transport` that determines which protocols
/// should be used to send and receive DNS wire data over the network.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum TransportType {

    /// Send packets over UDP or TCP.
    /// UDP is used by default. If the request packet would be too large, send
    /// a TCP packet instead; if a UDP _response_ packet is truncated, try
    /// again with TCP.
    Automatic,

    /// Send packets over UDP only.
    /// If the request packet is too large or the response packet is
    /// truncated, fail with an error.
    UDP,

    /// Send packets over TCP only.
    TCP,

    /// Send encrypted DNS-over-TLS packets.
    TLS,

    /// Send encrypted DNS-over-HTTPS packets.
    HTTPS,
}

impl TransportType {

    /// Creates a boxed `Transport` depending on the transport type.
    pub fn make_transport(self, ns: Nameserver) -> Box<dyn Transport> {
        match self {
            Self::Automatic  => Box::new(AutoTransport::new(ns)),
            Self::UDP        => Box::new(UdpTransport::new(ns)),
            Self::TCP        => Box::new(TcpTransport::new(ns)),
            Self::TLS        => Box::new(TlsTransport::new(ns)),
            Self::HTTPS      => Box::new(HttpsTransport::new(ns)),
        }
    }
}
