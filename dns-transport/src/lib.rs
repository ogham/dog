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
#![allow(clippy::wildcard_imports)]

#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(unsafe_code)]

use std::time::Duration;

mod address;
pub use self::address::{parse_host_port, parse_https_url, HttpsUrl, InvalidAddress};

mod auto;
pub use self::auto::AutoTransport;

mod error;
pub use self::error::Error;

mod failover;
pub use self::failover::FailoverTransport;

mod net;

mod udp;
pub use self::udp::UdpTransport;

mod tcp;
pub use self::tcp::TcpTransport;

#[cfg(feature = "with_tls")]
mod tls;
#[cfg(feature = "with_tls")]
pub use self::tls::TlsTransport;

#[cfg(feature = "with_https")]
mod https;
#[cfg(feature = "with_https")]
pub use self::https::HttpsTransport;

#[cfg(feature = "with_https")]
mod h2;

#[cfg(any(feature = "with_tls", feature = "with_https"))]
mod tls_stream;


/// How long dog waits for a server, first to accept a connection and then
/// to answer, before giving up. Each transport can be given a different
/// limit with its `with_timeout` constructor.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The trait implemented by all transport types.
pub trait Transport {

    /// Convert the request to bytes, send it over the network, wait for a
    /// response, deserialise it from bytes, and return it.
    ///
    /// # Errors
    ///
    /// Returns an `Error` error if there’s an I/O error sending or
    /// receiving data, the server does not answer in time, the DNS packet
    /// in the response contained invalid bytes and failed to parse, the
    /// response does not answer the request, or there was a protocol-level
    /// error for the TLS and HTTPS transports.
    fn send(&self, request: &dns::Request) -> Result<dns::Response, Error>;
}


#[cfg(test)]
pub(crate) mod test_util {
    use std::time::Duration;

    use dns::record::RecordType;

    /// A timeout short enough to keep tests of silent servers quick.
    pub const SHORT: Duration = Duration::from_millis(300);

    /// The request that the captured `a-example` fixtures answer.
    pub fn a_example() -> dns::Request {
        dns::Request {
            transaction_id: 0x1234,
            flags: dns::Flags::query(),
            query: dns::Query {
                qname: dns::Labels::encode("a-example.lookup.dog").unwrap(),
                qtype: RecordType::A,
                qclass: dns::QClass::IN,
            },
            additional: Some(dns::Request::additional_record()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn default_timeout_is_five_seconds() {
        assert_eq!(DEFAULT_TIMEOUT, Duration::from_secs(5));
    }
}
