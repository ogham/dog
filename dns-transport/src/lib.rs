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
#![allow(clippy::option_if_let_else)]
#![allow(clippy::pub_enum_variant_names)]
#![allow(clippy::wildcard_imports)]

#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(unsafe_code)]

use async_trait::async_trait;
use derive_more::From;

use dns::{Request, Response};


// Re-export the five transport types, as well as the Tokio runtime, so that
// the dog crate can just use something called “Runtime” without worrying
// about which runtime it actually is.

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

pub use tokio::runtime::Runtime;



/// The trait implemented by all four transport types.
#[async_trait]
pub trait Transport {

    /// Convert the request to bytes, send it over the network, wait for a
    /// response, deserialise it from bytes, and return it, asynchronously.
    async fn send(&self, request: &Request) -> Result<Response, Error>;
}

/// Something that can go wrong making a DNS request.
#[derive(Debug, From)]  // can't be PartialEq due to tokio error
pub enum Error {

    /// There was a problem with the network sending the request or receiving
    /// a response asynchorously.
    NetworkError(tokio::io::Error),

    /// There was a problem making an HTTPS request.
    #[cfg(feature="https")]
    HttpError(hyper::Error),

    /// There was a problem making a TLS request.
    #[cfg(feature="tls")]
    TlsError(native_tls::Error),

    /// The data in the response did not parse correctly from the DNS wire
    /// protocol format.
    WireError(dns::WireError),

    /// The server specifically indicated that the request we sent it was
    /// malformed.
    BadRequest,
}
