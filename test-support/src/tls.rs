//! TLS versions of the mock servers, using the throwaway certificates in
//! `tests/fixtures/tls` (see `make-certs.sh` there).

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use native_tls::{Certificate, Identity, TlsAcceptor, TlsConnector, TlsStream};

use crate::fixtures;
use crate::mock::{self, Http, Http2, Log, Server, Tcp};

/// The path of the test CA certificate, for `SSL_CERT_FILE`.
pub fn ca_path() -> PathBuf {
    fixtures::root().join("tls").join("ca.pem")
}

/// The test CA certificate.
///
/// # Panics
///
/// Panics if the fixture is missing or does not parse.
pub fn test_ca() -> Certificate {
    Certificate::from_pem(&fixtures::load("tls/ca.pem")).expect("the test CA parses")
}

/// A client connector that trusts the test CA as well as the system roots.
///
/// # Panics
///
/// Panics if the connector cannot be built.
pub fn connector() -> TlsConnector {
    TlsConnector::builder().add_root_certificate(test_ca()).build().expect("build a TLS connector")
}

/// An acceptor that agrees to the given application protocols (ALPN), if the
/// client offers them; with none, it chooses none, and the client uses its
/// default.
fn acceptor(protocols: &[&str]) -> TlsAcceptor {
    let certificate = fixtures::load("tls/localhost.pem");
    let key = fixtures::load("tls/localhost.key");
    let identity = Identity::from_pkcs8(&certificate, &key).expect("the test identity parses");
    TlsAcceptor::builder(identity).accept_alpn(protocols).build().expect("build a TLS acceptor")
}

/// What a TLS server does with each connection.
#[derive(Debug, Clone)]
pub enum Tls {

    /// Complete the handshake, then serve DNS over TCP (DNS-over-TLS).
    Dns(Tcp),

    /// Complete the handshake, then serve HTTP (DNS-over-HTTPS).
    Http(Http),

    /// Complete the handshake, choosing HTTP/2 by ALPN, then serve HTTP/2.
    Http2(Http2),

    /// Answer the client’s handshake with bytes that are not TLS.
    GarbageHandshake,

    /// Accept the connection but never answer the handshake.
    SilentHandshake,
}

/// Starts a TLS server on an ephemeral loopback port, presenting a
/// certificate for `localhost` and `127.0.0.1` signed by the test CA.
///
/// # Panics
///
/// Panics if the listener cannot be bound or the certificates don’t load.
pub fn tls(mode: Tls) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback TCP listener");
    let protocols: &[&str] = if matches!(mode, Tls::Http2(_)) { &[ "h2" ] } else { &[] };
    let acceptor = acceptor(protocols);
    mock::spawn_tcp(listener, move |stream, log| handle(stream, &mode, &acceptor, log))
}

fn handle(mut stream: TcpStream, mode: &Tls, acceptor: &TlsAcceptor, log: &Log) {
    mock::prepare(&stream);
    match mode {
        Tls::GarbageHandshake => {
            if let Err(e) = stream.write_all(b"this is not a TLS handshake\r\n") {
                eprintln!("mock TLS server: could not send garbage: {e}");
            }
        }
        Tls::SilentHandshake => {
            if let Err(e) = mock::hold(&mut stream) {
                eprintln!("mock TLS server: connection failed: {e}");
            }
        }
        Tls::Dns(tcp) => with_tls(stream, acceptor, |tls| mock::serve_dns_stream(tls, tcp, log)),
        Tls::Http(http) => with_tls(stream, acceptor, |tls| mock::serve_http_stream(tls, http, log)),
        Tls::Http2(h2) => with_tls(stream, acceptor, |tls| mock::serve_http2_stream(tls, h2, log)),
    }
}

fn with_tls(stream: TcpStream, acceptor: &TlsAcceptor, serve: impl FnOnce(&mut TlsStream<TcpStream>)) {
    match acceptor.accept(stream) {
        Ok(mut tls) => {
            serve(&mut tls);
            if let Err(e) = tls.shutdown() {
                eprintln!("mock TLS server: shutdown failed: {e}");
            }
        }
        Err(e) => eprintln!("mock TLS server: handshake failed: {e}"),
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::io::Read;
    use crate::wire;

    const REPLY: &[u8] = &[ 0xaa, 0xaa, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0 ];
    const QUERY: &[u8] = &[ 0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 ];

    #[test]
    fn serves_dns_over_tls_to_a_client_trusting_the_test_ca() {
        let server = tls(Tls::Dns(Tcp::Replay(REPLY.to_vec())));
        let tcp = TcpStream::connect(server.addr()).unwrap();
        let mut stream = connector().connect("localhost", tcp).unwrap();
        stream.write_all(&mock::prefixed(QUERY)).unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert_eq!(reply, mock::prefixed(&wire::with_txid(REPLY, 0x1234)));
        assert_eq!(server.requests(), vec![ QUERY.to_vec() ]);
    }

    #[test]
    fn certificate_is_valid_for_the_loopback_address() {
        let server = tls(Tls::Http(Http::Raw(b"HTTP/1.1 204 No Content\r\n\r\n".to_vec())));
        let tcp = TcpStream::connect(server.addr()).unwrap();
        let mut stream = connector().connect("127.0.0.1", tcp).unwrap();
        stream.write_all(b"POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n").unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        assert!(reply.starts_with(b"HTTP/1.1 204"));
    }

    /// A client offering HTTP/2 gets it from an HTTP/2 server, and gets no
    /// protocol from the others, which leaves it on HTTP/1.1.
    #[test]
    fn http2_is_chosen_by_alpn() {
        let offering = || TlsConnector::builder().add_root_certificate(test_ca()).request_alpns(&[ "h2", "http/1.1" ]).build().unwrap();

        let server = tls(Tls::Http2(Http2::Raw(Vec::new())));
        let stream = offering().connect("localhost", TcpStream::connect(server.addr()).unwrap()).unwrap();
        assert_eq!(stream.negotiated_alpn().unwrap().as_deref(), Some(&b"h2"[..]));

        let server = tls(Tls::Http(Http::Silent));
        let stream = offering().connect("localhost", TcpStream::connect(server.addr()).unwrap()).unwrap();
        assert_eq!(stream.negotiated_alpn().unwrap(), None);
    }

    #[test]
    fn untrusted_without_the_test_ca() {
        let server = tls(Tls::Dns(Tcp::Silent));
        let tcp = TcpStream::connect(server.addr()).unwrap();
        assert!(TlsConnector::new().unwrap().connect("localhost", tcp).is_err());
    }

    #[test]
    fn garbage_handshake_fails() {
        let server = tls(Tls::GarbageHandshake);
        let tcp = TcpStream::connect(server.addr()).unwrap();
        assert!(connector().connect("localhost", tcp).is_err());
        assert!(ca_path().ends_with("tls/ca.pem"));
    }
}
