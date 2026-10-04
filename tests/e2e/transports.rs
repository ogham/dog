//! Each transport, against a loopback server.

use std::time::{Duration, Instant};

use test_support::fixtures;
use test_support::mock::{self, Tcp, Udp};

use crate::common::{dog, run, Run};

#[test]
fn tcp_replay() {
    let server = mock::tcp(Tcp::Replay(fixtures::response("a-example-tcp")));
    let run = Run::of(dog().args([ "-T", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (0, "10.20.30.40\n", ""));
    assert_eq!(server.requests().len(), 1);
}

#[test]
fn tcp_reply_arriving_one_byte_at_a_time() {
    let server = mock::tcp(Tcp::Drip(fixtures::response("a-example-tcp")));
    let run = Run::of(dog().args([ "-T", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((run.status, run.stdout.as_str()), (0, "10.20.30.40\n"));
}

#[test]
fn tcp_reply_larger_than_one_read() {
    let server = mock::tcp(Tcp::Replay(fixtures::response("txt-big-tcp")));
    let run = Run::of(dog().args([ "-T", "--short", "TXT", "big.dogtest.example" ]).arg(server.at()));
    assert_eq!(run.status, 0, "{run:?}");
    assert_eq!(run.stdout.lines().count(), 20);
}

/// The automatic transport asks over UDP, sees the truncated flag in the
/// real truncated answer, and asks again over TCP on the same port.
#[test]
fn automatic_transport_retries_truncated_answers_over_tcp() {
    let (udp, tcp) = mock::udp_and_tcp(
        Udp::Replay(fixtures::response("tc-txt-google")),
        Tcp::Replay(fixtures::response("tc-txt-google-tcp")),
    );
    let run = Run::of(dog().args([ "--short", "--edns", "disable", "TXT", "google.com" ]).arg(udp.at()));
    assert_eq!(run.status, 0, "{run:?}");
    assert!(run.stdout.contains("v=spf1"), "{}", run.stdout);
    assert_eq!((udp.requests().len(), tcp.requests().len()), (1, 1));
}

#[test]
fn automatic_transport_keeps_untruncated_udp_answers() {
    let (udp, tcp) = mock::udp_and_tcp(
        Udp::Replay(fixtures::response("a-example")),
        Tcp::Replay(fixtures::response("a-example-tcp")),
    );
    let run = Run::of(dog().args([ "--short", "a-example.lookup.dog" ]).arg(udp.at()));
    assert_eq!((run.status, run.stdout.as_str()), (0, "10.20.30.40\n"));
    assert_eq!((udp.requests().len(), tcp.requests().len()), (1, 0));
}

/// `--timeout` changes how long dog waits: a caller running its own recursive
/// resolver sets it above the resolver's give-up time, and a short one gives
/// up sooner. Fractions of a second are allowed.
#[test]
fn a_silent_server_times_out_after_the_timeout_asked_for() {
    let server = mock::udp(Udp::Silent);
    let started = Instant::now();
    let run = Run::of(dog().args([ "-U", "--timeout", "1.5", "a-example.lookup.dog" ]).arg(server.at()));
    let elapsed = started.elapsed();

    assert_eq!((run.status, run.stderr.as_str()), (1, "Error [network]: Timed out after 1.5s waiting for a response\n"));
    assert!(elapsed >= Duration::from_millis(1400) && elapsed < Duration::from_secs(4), "{elapsed:?}");
}

/// A `--timeout` longer than the default lets a slow server answer.
#[test]
fn a_longer_timeout_waits_past_five_seconds() {
    let server = mock::udp(Udp::Silent);
    let started = Instant::now();
    let run = Run::of(dog().args([ "-U", "--timeout", "7", "a-example.lookup.dog" ]).arg(server.at()));
    let elapsed = started.elapsed();

    assert_eq!((run.status, run.stderr.as_str()), (1, "Error [network]: Timed out after 7s waiting for a response\n"));
    assert!(elapsed >= Duration::from_millis(6500) && elapsed < Duration::from_secs(10), "{elapsed:?}");
}

/// With nothing to say how long to wait, dog gives up on a silent server
/// after five seconds.
#[test]
fn a_silent_server_times_out_after_five_seconds() {
    let server = mock::udp(Udp::Silent);
    let started = Instant::now();
    let run = Run::of(dog().args([ "-U", "a-example.lookup.dog" ]).arg(server.at()));
    let elapsed = started.elapsed();

    assert_eq!((run.status, run.stderr.as_str()), (1, "Error [network]: Timed out after 5s waiting for a response\n"));
    assert!(elapsed >= Duration::from_millis(4500) && elapsed < Duration::from_secs(8), "{elapsed:?}");
}

/// A forged datagram arriving before the real answer is ignored.
#[test]
fn a_forged_udp_answer_is_ignored() {
    let server = mock::udp(Udp::WrongTxidThen(fixtures::response("a-example")));
    let run = Run::of(dog().args([ "-U", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (0, "10.20.30.40\n", ""));
}

#[test]
fn a_tcp_answer_to_another_query_is_an_error() {
    let server = mock::tcp(Tcp::WrongTxid(fixtures::response("a-example-tcp")));
    let run = Run::of(dog().args([ "-T", "--txid", "0x1234", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
               (1, "", "Error [protocol]: Response ID 0x1235 does not match request ID 0x1234\n"));
}

#[test]
fn a_tcp_answer_cut_short_is_an_error() {
    let server = mock::tcp(Tcp::HalfBodyThenClose(fixtures::response("a-example-tcp")));
    let run = Run::of(dog().args([ "-T", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((run.status, run.stderr.as_str()), (1, "Error [network]: Truncated response\n"));
}

/// `--class 1` used to be sent as a class numbered 1 that dog did not think
/// was IN, so every answer, being for IN, was thrown away as answering some
/// other question, and the query timed out.
#[test]
fn a_numbered_class_is_the_named_class() {
    let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
    let run = Run::of(dog().args([ "-U", "--short", "--class", "1", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (0, "10.20.30.40\n", ""));
}

/// Hosts that cannot be hosts used to be looked up anyway, failing with the
/// system resolver’s message; a URL given to another transport was said to
/// have a port that was not a number.
#[test]
fn nameservers_that_cannot_be_addresses() {
    let cases: &[(&[&str], &str)] = &[
        (&[ "a.example", "@127.0.0.1:dns" ], r#"dog: Invalid options: Invalid nameserver "127.0.0.1:dns": its port is not a number from 0 to 65535"#),
        (&[ "-T", "a.example", "@[::1" ], r#"dog: Invalid options: Invalid nameserver "[::1": its '[' is never closed"#),
        (&[ "a.example", "@@127.0.0.1:53" ], r#"dog: Invalid options: Invalid nameserver "@127.0.0.1:53": its host is not an IP address or a host name"#),
        (&[ "a.example", "@127.0.0.1:53:9" ], r#"dog: Invalid options: Invalid nameserver "127.0.0.1:53:9": its host is not an IP address or a host name"#),
        (&[ "-T", "a.example", "@https://dns.google/dns-query" ], r#"dog: Invalid options: Invalid nameserver "https://dns.google/dns-query": it is a URL, which only DNS-over-HTTPS can use"#),
    ];

    for (args, message) in cases {
        let run = run(args);
        assert_eq!((run.status, run.stdout.as_str(), run.stderr.trim_end()), (3, "", *message), "{args:?}");
    }
}

#[cfg(feature = "with_tls")]
mod tls {
    use super::*;
    use test_support::tls::{self, Tls};

    #[test]
    fn dns_over_tls_to_a_trusted_server() {
        let server = tls::tls(Tls::Dns(Tcp::Replay(fixtures::response("a-example-tcp"))));
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path())
            .args([ "--tls", "--short", "a-example.lookup.dog" ]).arg(server.at()));
        assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (0, "10.20.30.40\n", ""));
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn dns_over_tls_to_an_untrusted_server() {
        let server = tls::tls(Tls::Dns(Tcp::Replay(fixtures::response("a-example-tcp"))));
        let run = Run::of(dog().args([ "--tls", "a-example.lookup.dog" ]).arg(server.at()));
        assert_eq!(run.status, 1);
        assert!(run.stderr.starts_with("Error [tls]: "), "{}", run.stderr);
        assert!(run.stderr.contains("certificate verify failed"), "{}", run.stderr);
    }

    #[test]
    fn dns_over_tls_to_something_that_does_not_speak_tls() {
        let server = tls::tls(Tls::GarbageHandshake);
        let run = Run::of(dog().args([ "--tls", "a-example.lookup.dog" ]).arg(server.at()));
        assert_eq!(run.status, 1);
        assert!(run.stderr.starts_with("Error [tls]: "), "{}", run.stderr);
    }

    /// A server that sends its answer a byte at a time, each well within the
    /// timeout, used to hold dog for as long as it went on sending.
    #[test]
    fn an_answer_trickled_out_a_byte_at_a_time() {
        let server = tls::tls(Tls::Dns(Tcp::Trickle(fixtures::response("a-example-tcp"), Duration::from_secs(1))));
        let started = Instant::now();
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path()).args([ "--tls", "a-example.lookup.dog" ]).arg(server.at()));
        let elapsed = started.elapsed();

        assert_eq!((run.status, run.stderr.as_str()), (1, "Error [network]: Timed out after 5s waiting for a response\n"));
        assert!(elapsed >= Duration::from_millis(4500) && elapsed < Duration::from_secs(8), "{elapsed:?}");
    }

    #[test]
    fn a_tls_nameserver_with_a_bad_port() {
        let run = run(&[ "--tls", "a.example", "@127.0.0.1:" ]);
        assert_eq!((run.status, run.stderr.as_str()),
                   (3, "dog: Invalid options: Invalid nameserver \"127.0.0.1:\": its port is not a number from 0 to 65535\n"));
    }
}

#[cfg(feature = "with_https")]
mod https {
    use super::*;
    use test_support::mock::{Http, Http2};
    use test_support::tls::{self, Tls};

    fn url(server: &mock::Server) -> String {
        format!("@https://localhost:{}/dns-query", server.port())
    }

    #[test]
    fn dns_over_https_to_a_trusted_server() {
        let server = tls::tls(Tls::Http(Http::Reply(fixtures::http_response("doh-cloudflare"))));
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path())
            .args([ "--https", "--short", "a-example.lookup.dog" ]).arg(url(&server)));
        assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (0, "10.20.30.40\n", ""));

        let expected_start = format!("POST /dns-query HTTP/1.1\r\nHost: localhost:{}\r\n", server.port());
        assert!(server.requests()[0].starts_with(expected_start.as_bytes()));
    }

    #[test]
    fn a_real_not_found_response() {
        let server = tls::tls(Tls::Http(Http::Reply(fixtures::http_response("doh-google-404"))));
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path())
            .args([ "--https", "a-example.lookup.dog" ]).arg(url(&server)));
        assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
                   (1, "", "Error [http]: Nameserver returned HTTP 404 (Not Found)\n"));
    }

    #[test]
    fn a_server_that_does_not_speak_http() {
        let server = tls::tls(Tls::Http(Http::Raw(b"SSH-2.0-OpenSSH_9.2\r\n\r\n".to_vec())));
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path())
            .args([ "--https", "a-example.lookup.dog" ]).arg(url(&server)));
        assert_eq!(run.status, 1);
        assert!(run.stderr.starts_with("Error [http]: "), "{}", run.stderr);
    }

    #[test]
    fn a_response_without_a_length() {
        let response = test_support::wire::map_http_headers(&fixtures::http_response("doh-cloudflare"), |line| {
            (!line.to_ascii_lowercase().starts_with("content-length:")).then(|| line.to_owned())
        });
        let server = tls::tls(Tls::Http(Http::Raw(response)));
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path())
            .args([ "--https", "a-example.lookup.dog" ]).arg(url(&server)));
        assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
                   (1, "", "Error [http]: The response has no Content-Length\n"));
    }

    #[test]
    fn a_url_without_a_path() {
        let run = run(&[ "--https", "a.example", "@https://localhost" ]);
        assert_eq!((run.status, run.stderr.as_str()),
                   (3, "dog: Invalid options: Invalid DNS-over-HTTPS URL \"https://localhost\": it has no path, such as '/dns-query'\n"));
    }

    /// The path used to go into the request as it was, so a line break in
    /// it added headers of the user’s choosing.
    #[test]
    fn a_url_with_a_line_break() {
        let run = run(&[ "--https", "a.example", "@https://localhost/x\r\nX-Evil: 1" ]);
        assert_eq!((run.status, run.stderr.as_str()),
                   (3, "dog: Invalid options: Invalid DNS-over-HTTPS URL \"https://localhost/x\\r\\nX-Evil: 1\": it contains a space, a control character, or a character that is not ASCII\n"));
    }

    #[test]
    fn a_response_trickled_out_a_byte_at_a_time() {
        let server = tls::tls(Tls::Http(Http::Trickle(fixtures::http_response("doh-google"), Duration::from_secs(1))));
        let started = Instant::now();
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path()).args([ "--https", "a-example.lookup.dog" ]).arg(url(&server)));
        let elapsed = started.elapsed();

        assert_eq!((run.status, run.stderr.as_str()), (1, "Error [network]: Timed out after 5s waiting for a response\n"));
        assert!(elapsed >= Duration::from_millis(4500) && elapsed < Duration::from_secs(8), "{elapsed:?}");
    }

    /// A server that chooses HTTP/2 gets it. Quad9’s speaks nothing else,
    /// and used to answer dog’s HTTP/1.1 with “505 HTTP Version Not
    /// Supported”.
    #[test]
    fn dns_over_https_over_http2() {
        let server = tls::tls(Tls::Http2(Http2::Reply(fixtures::h2_response("doh2-quad9"))));
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path())
            .args([ "--https", "--short", "a-example.lookup.dog" ]).arg(url(&server)));
        assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (0, "10.20.30.40\n", ""));
        assert!(server.requests()[0].starts_with(test_support::wire::H2_PREFACE));
    }

    /// HTTP/2 has no reason phrases, so the status is all there is to say.
    #[test]
    fn a_real_http2_error() {
        let server = tls::tls(Tls::Http2(Http2::Raw(fixtures::h2_response("doh2-google-415"))));
        let run = Run::of(dog().env("SSL_CERT_FILE", tls::ca_path())
            .args([ "--https", "a-example.lookup.dog" ]).arg(url(&server)));
        assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (1, "", "Error [http]: Nameserver returned HTTP 415\n"));
    }
}
