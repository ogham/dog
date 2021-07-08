/// Something that can go wrong making a DNS request.
#[derive(Debug)]
pub enum Error {

    /// The data in the response did not parse correctly from the DNS wire
    /// protocol format.
    WireError(dns::WireError),

    /// There was a problem with the network making a TCP or UDP request.
    NetworkError(std::io::Error),

    /// Not enough information was received from the server before a `read`
    /// call returned zero bytes.
    TruncatedResponse,

    /// There was a problem making a TLS request.
    #[cfg(feature = "with_nativetls")]
    TlsError(native_tls::Error),

    /// There was a problem _establishing_ a TLS request.
    #[cfg(feature = "with_nativetls")]
    TlsHandshakeError(native_tls::HandshakeError<std::net::TcpStream>),

    /// Provided dns name is not valid
    #[cfg(feature = "with_rustls")]
    RustlsInvalidDnsNameError(webpki::InvalidDNSNameError),

    /// There was a problem decoding the response HTTP headers or body.
    #[cfg(feature = "with_https")]
    HttpError(httparse::Error),

    /// The HTTP response code was something other than 200 OK, along with the
    /// response code text, if present.
    #[cfg(feature = "with_https")]
    WrongHttpStatus(u16, Option<String>),
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

#[cfg(feature = "with_nativetls")]
impl From<native_tls::Error> for Error {
    fn from(inner: native_tls::Error) -> Self {
        Self::TlsError(inner)
    }
}

#[cfg(feature = "with_nativetls")]
impl From<native_tls::HandshakeError<std::net::TcpStream>> for Error {
    fn from(inner: native_tls::HandshakeError<std::net::TcpStream>) -> Self {
        Self::TlsHandshakeError(inner)
    }
}

#[cfg(feature = "with_rustls")]
impl From<webpki::InvalidDNSNameError> for Error {
    fn from(inner: webpki::InvalidDNSNameError) -> Self {
        Self::RustlsInvalidDnsNameError(inner)
    }
}

#[cfg(feature = "with_https")]
impl From<httparse::Error> for Error {
    fn from(inner: httparse::Error) -> Self {
        Self::HttpError(inner)
    }
}
