/// Something that can go wrong making a DNS request.
#[derive(Debug)]
pub enum Error {

    /// There was a problem with the network sending the request or receiving
    /// a response asynchorously.
    NetworkError(std::io::Error),

    /// There was a problem making a TLS request.
    #[cfg(feature="tls")]
    TlsError(native_tls::Error),

    /// There was a problem _establishing_ a TLS request.
    #[cfg(feature="tls")]
    TlsHandshakeError(native_tls::HandshakeError<std::net::TcpStream>),

    /// The data in the response did not parse correctly from the DNS wire
    /// protocol format.
    WireError(dns::WireError),

    /// The server specifically indicated that the request we sent it was
    /// malformed.
    BadRequest,
}


// From impls

impl From<dns::WireError> for Error {
    fn from(inner: dns::WireError) -> Self {
        Self::WireError(inner)
    }
}

impl From<std::io::Error> for Error {
    fn from(inner: std::io::Error) -> Error {
        Self::NetworkError(inner)
    }
}

#[cfg(feature="tls")]
impl From<native_tls::Error> for Error {
    fn from(inner: native_tls::Error) -> Error {
        Self::TlsError(inner)
    }
}

#[cfg(feature="tls")]
impl From<native_tls::HandshakeError<std::net::TcpStream>> for Error {
    fn from(inner: native_tls::HandshakeError<std::net::TcpStream>) -> Error {
        Self::TlsHandshakeError(inner)
    }
}
