//! Creating DNS transports based on the user’s input arguments.

use dns_transport::*;


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

    /// Creates a boxed `Transport` depending on the transport type. The
    /// parameter will be a URL for the HTTPS transport type, and a
    /// stringified address for the others.
    pub fn make_transport(self, param: String) -> Box<dyn Transport> {
        match self {
            Self::Automatic  => Box::new(AutoTransport::new(param)),
            Self::UDP        => Box::new(UdpTransport::new(param)),
            Self::TCP        => Box::new(TcpTransport::new(param)),
            Self::TLS        => Box::new(TlsTransport::new(param)),
            Self::HTTPS      => Box::new(HttpsTransport::new(param)),
        }
    }
}
