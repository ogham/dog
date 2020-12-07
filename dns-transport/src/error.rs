/// Something that can go wrong making a DNS request.
#[derive(Debug, thiserror::Error)]
pub enum Error {

    /// The data in the response did not parse correctly from the DNS wire
    /// protocol format.
    #[error("{0:#}")]
    WireError(#[from] dns::WireError),

    /// No dns resolvers could be detected on the system.
    #[error("No nameserver found")]
    NoNameservers,

    /// There was a problem with the network making a TCP or UDP request.
    #[error("{0:#}")]
    NetworkError(#[from] std::io::Error),

    /// Not enough information was received from the server before a `read`
    /// call returned zero bytes.
    #[error("Truncated response")]
    TruncatedResponse,

    /// There was a problem making a TLS request.
    #[cfg(feature="tls")]
    #[error("{0:#}")]
    TlsError(#[from] native_tls::Error),

    /// There was a problem _establishing_ a TLS request.
    #[cfg(feature="tls")]
    #[error("{0:#}")]
    TlsHandshakeError(#[from] native_tls::HandshakeError<std::net::TcpStream>),

    /// There was a problem decoding the response HTTP headers or body.
    #[cfg(feature="https")]
    #[error("{0:#}")]
    HttpError(#[from] httparse::Error),

    /// The HTTP response code was something other than 200 OK, along with the
    /// response code text, if present.
    #[cfg(feature="https")]
    #[error("Nameserver returned HTTP {0} ({1:?})")]
    WrongHttpStatus(u16, Option<String>),
}

impl Error {
    /// Returns the “phase” of operation where an error occurred. This gets shown
    /// to the user so they can debug what went wrong.
    pub fn erroneous_phase(&self) -> &'static str {
        match self {
            Error::WireError(_)          => "protocol",
            Error::NoNameservers         => "system",
            Error::TruncatedResponse     |
            Error::NetworkError(_)       => "network",
            #[cfg(feature="tls")]
            Error::TlsError(_)           |
            Error::TlsHandshakeError(_)  => "tls",
            #[cfg(feature="https")]
            Error::HttpError(_)          |
            Error::WrongHttpStatus(_,_)  => "http",
        }
    }
}
