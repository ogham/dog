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
    /// Takes an 'Option<u16>' for diffrent ports None uses the protocol default port
    Automatic(Option<u16>),

    /// Send packets over UDP only.
    /// If the request packet is too large or the response packet is
    /// truncated, fail with an error.
    /// Takes an 'Option<u16>' for diffrent ports None uses the protocol default port
    UDP(Option<u16>),

    /// Send packets over TCP only.
    /// Takes an 'Option<u16>' for diffrent ports None uses the protocol default port
    TCP(Option<u16>),

    /// Send encrypted DNS-over-TLS packets.
    /// Takes an 'Option<u16>' for diffrent ports None uses the protocol default port
    TLS(Option<u16>),

    /// Send encrypted DNS-over-HTTPS packets.
    /// Takes an 'Option<u16>' for diffrent ports None uses the protocol default port
    HTTPS(Option<u16>),
}

impl TransportType {

    /// Creates a boxed `Transport` depending on the transport type. The
    /// parameter will be a URL for the HTTPS transport type, and a
    /// stringified address for the others.
    pub fn make_transport(self, param: String) -> Box<dyn Transport> {
        match self {
            Self::Automatic(p)  => Box::new(AutoTransport::new(param, p)),
            Self::UDP(p)        => Box::new(UdpTransport::new(param, p)),
            Self::TCP(p)        => Box::new(TcpTransport::new(param, p)),
            Self::TLS(p)        => Box::new(TlsTransport::new(param, p)),
            Self::HTTPS(p)      => Box::new(HttpsTransport::new(param, p)),
        }
    }
}
