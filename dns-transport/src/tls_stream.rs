//! Opening TLS connections, for the TLS and HTTPS transports.

use std::net::TcpStream;
use std::time::Duration;

use native_tls::{HandshakeError, TlsConnector, TlsStream};

use super::{net, Error};
use super::net::{Deadline, DeadlineStream};


/// A TLS connection whose every read and write keeps to one deadline.
pub(crate) type Stream = TlsStream<DeadlineStream<TcpStream>>;

/// Connects to the host and port and performs a TLS handshake, all before
/// the deadline, trusting the certificates the system’s TLS library trusts.
/// The server is offered the given application protocols (ALPN, RFC 7301),
/// if there are any, to choose one from.
pub(crate) fn connect(host: &str, port: u16, deadline: Deadline, protocols: &[&str]) -> Result<Stream, Error> {
    let connector = TlsConnector::builder().request_alpns(protocols).build().map_err(Error::TlsError)?;
    let stream = net::connect_tcp(host, port, deadline)?;
    connector.connect(host, stream).map_err(|e| handshake_error(e, deadline.timeout()))
}

/// A stream that runs out of time during the handshake reports that the
/// handshake would block, which for dog’s blocking sockets means it timed out.
fn handshake_error<S>(error: HandshakeError<S>, timeout: Duration) -> Error {
    match error {
        HandshakeError::WouldBlock(_)  => Error::Timeout(timeout),
        HandshakeError::Failure(e)     => Error::TlsHandshakeError(e),
    }
}
