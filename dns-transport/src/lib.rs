//! All the DNS transport types.

#![warn(deprecated_in_future)]
#![warn(future_incompatible)]
#![warn(missing_copy_implementations)]
#![warn(missing_docs)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts, trivial_numeric_casts)]
#![warn(unused)]

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::pub_enum_variant_names)]
#![allow(clippy::wildcard_imports)]

#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(unsafe_code)]


mod auto;
pub use self::auto::AutoTransport;

mod udp;
pub use self::udp::UdpTransport;

mod tcp;
pub use self::tcp::TcpTransport;

mod tls;
pub use self::tls::TlsTransport;

mod https;
pub use self::https::HttpsTransport;

mod error;
pub use self::error::Error;


/// The trait implemented by all transport types.
pub trait Transport {

    /// Convert the request to bytes, send it over the network, wait for a
    /// response, deserialise it from bytes, and return it, asynchronously.
    ///
    /// # Errors
    ///
    /// Returns an `Error` error if there’s an I/O error sending or
    /// receiving data, or the DNS packet in the response contained invalid
    /// bytes and failed to parse, or if there was a protocol-level error for
    /// the TLS and HTTPS transports.
    fn send(&self, request: &dns::Request) -> Result<dns::Response, Error>;
}


use std::net::SocketAddr;
use std::io::ErrorKind;
use url::Url;

// parse address:port literals in the style of RFC2732:
// [2001:db8::1]
// [2001:db8::2]:53
// 192.0.2.1
// 192.0.2.1:53
fn lookup_addr(addr: &str) -> Result<Vec<SocketAddr>, Error> {
    if addr.contains('/') {
        return Err(Error::NameserverError(std::io::Error::new(ErrorKind::InvalidInput, "contains invalid characters")));
    }

    // cheat and just parse the pseudo-url "dns://<address>"
    let url = Url::parse(format!("dns://{}/", addr).as_str()).map_err(
            |e| Error::NameserverError(std::io::Error::new(ErrorKind::InvalidInput, e)))?;

    // This resolves the URL in to 1 or more SocketAddr's (or errors)
    url.socket_addrs(|| Some(53)).map_err(Error::NameserverError)
}