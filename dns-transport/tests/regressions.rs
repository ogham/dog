//! Regression tests for bugs found in dog’s transports. Each used to hang,
//! panic, or accept an answer to a different question. They only use the
//! transports’ basic constructors, so they ran against the old code too,
//! and failed there.

use std::time::Duration;

use dns::{Flags, Labels, QClass, Query, Request, Response};
use dns::record::RecordType;
use dns_transport::{Error, TcpTransport, Transport, UdpTransport};
use test_support::fixtures;
use test_support::mock::{self, Tcp, Udp};
use test_support::watchdog;

/// Longer than any correct exchange here takes, including dog’s own
/// five-second timeout; reaching it means dog is stuck.
const HANG: Duration = Duration::from_secs(15);

fn request() -> Request {
    Request {
        transaction_id: 0x1234,
        flags: Flags::query(),
        query: Query {
            qname: Labels::encode("a-example.lookup.dog").unwrap(),
            qtype: RecordType::A,
            qclass: QClass::IN,
        },
        additional: Some(Request::additional_record()),
    }
}

fn send_tcp(mode: Tcp) -> Result<Response, Error> {
    let server = mock::tcp(mode);
    let addr = server.addr().to_string();
    watchdog::within(HANG, move || TcpTransport::new(addr).send(&request()))
}

fn send_udp(mode: Udp) -> Result<Response, Error> {
    let server = mock::udp(mode);
    let addr = server.addr().to_string();
    watchdog::within(HANG, move || UdpTransport::new(addr).send(&request()))
}

/// A server that closed the connection partway through its answer left
/// dog reading forever at full CPU: the loop checked the wrong length.
#[test]
fn tcp_answer_cut_off_mid_message() {
    let result = send_tcp(Tcp::HalfBodyThenClose(fixtures::response("a-example-tcp")));
    assert!(matches!(result, Err(Error::TruncatedResponse)), "{result:?}");
}

#[test]
fn tcp_answer_cut_off_after_its_length() {
    let result = send_tcp(Tcp::PrefixOnlyThenClose(fixtures::response("a-example-tcp")));
    assert!(matches!(result, Err(Error::TruncatedResponse)), "{result:?}");
}

/// A server that never answered left dog waiting forever.
#[test]
fn tcp_server_that_never_answers() {
    assert!(send_tcp(Tcp::Silent).is_err());
}

#[test]
fn udp_server_that_never_answers() {
    assert!(send_udp(Udp::Silent).is_err());
}

/// An answer with a different transaction ID was taken as the answer.
#[test]
fn tcp_answer_to_a_different_query() {
    assert!(send_tcp(Tcp::WrongTxid(fixtures::response("a-example-tcp"))).is_err());
}

/// Over UDP, a stray datagram with the wrong ID must be skipped, and the
/// real answer that follows it taken instead.
#[test]
fn udp_stray_datagram_before_the_answer() {
    let response = send_udp(Udp::WrongTxidThen(fixtures::response("a-example"))).unwrap();
    assert_eq!(response.transaction_id, 0x1234);
}

/// A query, rather than a response, was taken as the answer.
#[test]
fn udp_query_instead_of_an_answer() {
    let server = mock::udp(Udp::NotAResponse(fixtures::response("a-example")));
    let addr = server.addr().to_string();
    let result = watchdog::within(HANG, move || UdpTransport::new(addr).send(&request()));
    assert!(result.is_err(), "{result:?}");
}

/// A nameserver argument with a bad port made dog panic.
#[cfg(feature = "with_tls")]
#[test]
fn tls_nameserver_with_a_bad_port() {
    use dns_transport::TlsTransport;

    for addr in [ "127.0.0.1:dns", "127.0.0.1:", "127.0.0.1:99999" ] {
        let result = watchdog::within(HANG, move || TlsTransport::new(addr.into()).send(&request()));
        assert!(result.is_err(), "{addr}: {result:?}");
    }
}

/// A DNS-over-HTTPS URL without a path made dog panic.
#[cfg(feature = "with_https")]
#[test]
fn https_url_without_a_path() {
    use dns_transport::HttpsTransport;

    for url in [ "https://example.com", "http://example.com/dns-query", "example.com/dns-query" ] {
        let result = watchdog::within(HANG, move || HttpsTransport::new(url.into()).send(&request()));
        assert!(result.is_err(), "{url}: {result:?}");
    }
}
