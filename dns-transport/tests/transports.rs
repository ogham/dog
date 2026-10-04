//! Each transport against loopback servers that replay real captured
//! responses, including the ways servers go wrong.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use dns::{Flags, Labels, Mismatch, QClass, Query, Request, Response, WireError};
use dns::record::RecordType;
use dns_transport::*;
use test_support::fixtures;
use test_support::mock::{self, Tcp, Udp};
use test_support::wire;

/// Short enough to keep tests of silent servers quick.
const SHORT: Duration = Duration::from_millis(300);

fn request(qname: &str, qtype: RecordType, edns: bool) -> Request {
    Request {
        transaction_id: 0x1234,
        flags: Flags::query(),
        query: Query { qname: Labels::encode(qname).unwrap(), qtype, qclass: QClass::IN },
        additional: edns.then(Request::additional_record),
    }
}

fn a_example() -> Request {
    request("a-example.lookup.dog", RecordType::A, true)
}

fn closed_port() -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.local_addr().unwrap().to_string()
}

/// Asserts that the result is a timeout, reached no sooner than it should be.
fn assert_times_out(started: Instant, result: Result<Response, Error>) {
    assert!(matches!(result, Err(Error::Timeout(SHORT))), "{result:?}");
    assert!(started.elapsed() >= SHORT, "{:?}", started.elapsed());
}


mod udp {
    use super::*;

    fn send(mode: Udp, request: &Request) -> Result<Response, Error> {
        let server = mock::udp(mode);
        UdpTransport::with_timeout(server.addr().to_string(), SHORT).send(request)
    }

    #[test]
    fn a_real_answer() {
        let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
        let response = UdpTransport::new(server.addr().to_string()).send(&a_example()).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(server.requests(), vec![ a_example().to_bytes().unwrap() ]);
    }

    #[test]
    fn a_stray_answer_then_the_real_one() {
        let response = send(Udp::WrongTxidThen(fixtures::response("a-example")), &a_example()).unwrap();
        assert_eq!(response.transaction_id, 0x1234);
    }

    #[test]
    fn nothing_but_stray_answers() {
        let started = Instant::now();
        assert_times_out(started, send(Udp::OnlyWrongTxid(fixtures::response("a-example")), &a_example()));
    }

    #[test]
    fn a_query_instead_of_an_answer() {
        let started = Instant::now();
        assert_times_out(started, send(Udp::NotAResponse(fixtures::response("a-example")), &a_example()));
    }

    #[test]
    fn an_answer_to_another_question() {
        let started = Instant::now();
        assert_times_out(started, send(Udp::Replay(fixtures::response("aaaa-example")), &a_example()));
    }

    #[test]
    fn a_broken_answer_with_the_right_id() {
        let broken = wire::truncate(&fixtures::response("a-example"), 20);
        let result = send(Udp::RawWithTxid(broken), &a_example());
        assert!(matches!(result, Err(Error::WireError(WireError::IO))), "{result:?}");
    }

    #[test]
    fn noise() {
        let started = Instant::now();
        assert_times_out(started, send(Udp::Raw(vec![ 1, 2, 3 ]), &a_example()));
    }

    #[test]
    fn silence() {
        let started = Instant::now();
        assert_times_out(started, send(Udp::Silent, &a_example()));
    }

    #[test]
    fn a_closed_port() {
        let result = UdpTransport::with_timeout(closed_port(), SHORT).send(&a_example());
        assert!(matches!(result, Err(Error::NetworkError(_))), "{result:?}");
    }

    #[test]
    fn an_invalid_address() {
        let result = UdpTransport::new("127.0.0.1:dns".into()).send(&a_example());
        assert!(matches!(result, Err(Error::InvalidNameserver(_))), "{result:?}");
    }

    /// BIND’s answer is over 5000 bytes; dog advertises buffers up to
    /// 65535 bytes, so it must be able to receive a datagram that big.
    #[test]
    fn a_datagram_larger_than_4096_bytes() {
        let big = fixtures::response("txt-big-tcp");
        assert!(big.len() > 4096);
        let response = send(Udp::Replay(big), &request("big.dogtest.example", RecordType::TXT, true)).unwrap();
        assert_eq!(response.answers.len(), 20);
    }
}


mod tcp {
    use super::*;

    fn send(mode: Tcp) -> Result<Response, Error> {
        let server = mock::tcp(mode);
        TcpTransport::with_timeout(server.addr().to_string(), SHORT).send(&a_example())
    }

    /// A server that sent its answer a byte at a time, each well within the
    /// timeout, used to hold dog for as long as it kept sending, because the
    /// timeout applied to each read and not to the whole exchange.
    #[test]
    fn an_answer_trickled_out_a_byte_at_a_time() {
        let started = Instant::now();
        assert_times_out(started, send(Tcp::Trickle(fixtures::response("a-example-tcp"), SHORT / 3)));
        assert!(started.elapsed() < SHORT * 3, "{:?}", started.elapsed());
    }

    #[test]
    fn a_real_answer() {
        let server = mock::tcp(Tcp::Replay(fixtures::response("a-example-tcp")));
        let response = TcpTransport::new(server.addr().to_string()).send(&a_example()).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(server.requests(), vec![ a_example().to_bytes().unwrap() ]);
    }

    #[test]
    fn an_answer_one_byte_at_a_time() {
        assert!(send(Tcp::Drip(fixtures::response("a-example-tcp"))).is_ok());
    }

    #[test]
    fn a_real_answer_too_big_for_one_read() {
        let server = mock::tcp(Tcp::Replay(fixtures::response("dnskey-root-tcp")));
        let request = Request { additional: None, .. request(".", RecordType::DNSKEY, false) };
        let response = TcpTransport::new(server.addr().to_string()).send(&request).unwrap();
        assert!(response.answers.len() > 2);
    }

    #[test]
    fn bytes_after_the_answer() {
        assert!(send(Tcp::TrailingBytes(fixtures::response("a-example-tcp"))).is_ok());
    }

    #[test]
    fn answers_cut_short() {
        let answer = fixtures::response("a-example-tcp");
        for mode in [ Tcp::PrefixOnlyThenClose(answer.clone()), Tcp::HalfBodyThenClose(answer), Tcp::OneByteThenClose ] {
            let result = send(mode.clone());
            assert!(matches!(result, Err(Error::TruncatedResponse)), "{mode:?}: {result:?}");
        }
    }

    #[test]
    fn an_empty_answer() {
        assert!(matches!(send(Tcp::ZeroLength), Err(Error::WireError(WireError::IO))));
    }

    #[test]
    fn a_closed_connection() {
        let result = send(Tcp::CloseImmediately);
        assert!(matches!(result, Err(Error::TruncatedResponse | Error::NetworkError(_))), "{result:?}");
    }

    #[test]
    fn an_answer_to_a_different_query() {
        let result = send(Tcp::WrongTxid(fixtures::response("a-example-tcp")));
        assert!(matches!(result, Err(Error::MismatchedResponse(Mismatch::TransactionId { expected: 0x1234, received: 0x1235 }))), "{result:?}");
    }

    #[test]
    fn an_answer_to_a_different_question() {
        let result = send(Tcp::Replay(fixtures::response("tc-txt-google-tcp")));
        assert!(matches!(result, Err(Error::MismatchedResponse(Mismatch::Question { .. }))), "{result:?}");
    }

    #[test]
    fn silence() {
        let started = Instant::now();
        assert_times_out(started, send(Tcp::Silent));
    }

    #[test]
    fn a_closed_port() {
        let result = TcpTransport::with_timeout(closed_port(), SHORT).send(&a_example());
        assert!(matches!(result, Err(Error::NetworkError(_))), "{result:?}");
    }
}


mod auto {
    use super::*;

    fn google_txt() -> Request {
        request("google.com", RecordType::TXT, false)
    }

    #[test]
    fn an_answer_that_fits_stays_on_udp() {
        let (udp, tcp) = mock::udp_and_tcp(Udp::Replay(fixtures::response("a-example")), Tcp::Replay(fixtures::response("a-example-tcp")));
        let response = AutoTransport::new(udp.addr().to_string()).send(&a_example()).unwrap();
        assert!(!response.flags.truncated);
        assert_eq!((udp.requests().len(), tcp.requests().len()), (1, 0));
    }

    /// Cloudflare truncated its UDP answer for google.com’s TXT records and
    /// sent the whole answer over TCP.
    #[test]
    fn a_truncated_answer_is_asked_again_over_tcp() {
        let (udp, tcp) = mock::udp_and_tcp(Udp::Replay(fixtures::response("tc-txt-google")), Tcp::Replay(fixtures::response("tc-txt-google-tcp")));
        let response = AutoTransport::new(udp.addr().to_string()).send(&google_txt()).unwrap();
        assert!(!response.flags.truncated);
        assert!(!response.answers.is_empty());
        assert_eq!((udp.requests().len(), tcp.requests().len()), (1, 1));
    }

    #[test]
    fn a_failure_over_tcp_after_truncation() {
        let (udp, _tcp) = mock::udp_and_tcp(Udp::Replay(fixtures::response("tc-txt-google")), Tcp::CloseImmediately);
        assert!(AutoTransport::with_timeout(udp.addr().to_string(), SHORT).send(&google_txt()).is_err());
    }

    #[test]
    fn a_failure_over_udp_is_not_retried() {
        let result = AutoTransport::with_timeout(closed_port(), SHORT).send(&a_example());
        assert!(matches!(result, Err(Error::NetworkError(_))), "{result:?}");
    }
}


#[cfg(feature = "with_tls")]
mod tls {
    use super::*;
    use test_support::tls::{self, Tls};

    fn send(mode: Tls, timeout: Duration) -> Result<Response, Error> {
        let server = tls::tls(mode);
        TlsTransport::with_timeout(server.addr().to_string(), timeout).send(&a_example())
    }

    /// The system does not trust the test CA, so the handshake fails.
    #[test]
    fn an_untrusted_certificate() {
        let result = send(Tls::Dns(Tcp::Replay(fixtures::response("a-example-tcp"))), SHORT * 10);
        assert!(matches!(result, Err(Error::TlsHandshakeError(_))), "{result:?}");
    }

    #[test]
    fn a_server_that_does_not_speak_tls() {
        let result = send(Tls::GarbageHandshake, SHORT * 10);
        assert!(matches!(result, Err(Error::TlsHandshakeError(_))), "{result:?}");
    }

    #[test]
    fn a_handshake_that_never_finishes() {
        let started = Instant::now();
        assert_times_out(started, send(Tls::SilentHandshake, SHORT));
    }

    #[test]
    fn a_closed_port() {
        let result = TlsTransport::with_timeout(closed_port(), SHORT).send(&a_example());
        assert!(matches!(result, Err(Error::NetworkError(_))), "{result:?}");
    }

    #[test]
    fn an_invalid_port() {
        let result = TlsTransport::new("127.0.0.1:853853".into()).send(&a_example());
        assert!(matches!(result, Err(Error::InvalidNameserver(_))), "{result:?}");
    }
}


#[cfg(feature = "with_https")]
mod https {
    use super::*;
    use test_support::mock::Http;
    use test_support::tls::{self, Tls};

    fn url(server: &mock::Server) -> String {
        format!("https://localhost:{}/dns-query", server.port())
    }

    #[test]
    fn an_untrusted_certificate() {
        let server = tls::tls(Tls::Http(Http::Reply(fixtures::http_response("doh-cloudflare"))));
        let result = HttpsTransport::with_timeout(url(&server), SHORT * 10).send(&a_example());
        assert!(matches!(result, Err(Error::TlsHandshakeError(_))), "{result:?}");
    }

    #[test]
    fn a_handshake_that_never_finishes() {
        let server = tls::tls(Tls::SilentHandshake);
        let started = Instant::now();
        assert_times_out(started, HttpsTransport::with_timeout(url(&server), SHORT).send(&a_example()));
    }

    #[test]
    fn invalid_urls() {
        for url in [ "https://example.com", "http://example.com/dns-query", "https://example.com:dns/dns-query" ] {
            let result = HttpsTransport::new(url.into()).send(&a_example());
            assert!(matches!(result, Err(Error::InvalidNameserver(_))), "{url}: {result:?}");
        }
    }
}
