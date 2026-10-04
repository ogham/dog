use std::time::Duration;


/// Something that can go wrong making a DNS request.
#[derive(Debug)]
pub enum Error {

    /// The data in the response did not parse correctly from the DNS wire
    /// protocol format.
    WireError(dns::WireError),

    /// There was a problem with the network making a TCP or UDP request.
    NetworkError(std::io::Error),

    /// Not enough information was received from the server before the
    /// connection was closed.
    TruncatedResponse,

    /// The server did not accept the connection, or did not answer, within
    /// this time.
    Timeout(Duration),

    /// A response arrived that does not answer the request that was sent.
    MismatchedResponse(dns::Mismatch),

    /// The nameserver cannot be used as an address, with the reason why.
    InvalidNameserver(String),

    /// There was a problem making a TLS request.
    #[cfg(any(feature = "with_tls", feature = "with_https"))]
    TlsError(native_tls::Error),

    /// There was a problem _establishing_ a TLS request.
    #[cfg(any(feature = "with_tls", feature = "with_https"))]
    TlsHandshakeError(native_tls::Error),

    /// There was a problem decoding the response HTTP headers or body.
    #[cfg(feature = "with_https")]
    HttpError(httparse::Error),

    /// The HTTP response code was something other than 200 OK, along with the
    /// response code text, if present.
    #[cfg(feature = "with_https")]
    WrongHttpStatus(u16, Option<String>),

    /// The HTTP response cannot be read as a DNS answer, with the reason why.
    #[cfg(feature = "with_https")]
    MalformedHttp(String),
}


// From impls

impl From<dns::WireError> for Error {
    fn from(inner: dns::WireError) -> Self {
        Self::WireError(inner)
    }
}

impl From<std::io::Error> for Error {
    fn from(inner: std::io::Error) -> Self {
        Self::NetworkError(inner)
    }
}

impl From<dns::Mismatch> for Error {
    fn from(inner: dns::Mismatch) -> Self {
        Self::MismatchedResponse(inner)
    }
}

#[cfg(feature = "with_https")]
impl From<httparse::Error> for Error {
    fn from(inner: httparse::Error) -> Self {
        Self::HttpError(inner)
    }
}
