//! dog’s exit status, and what it prints, in each way a run can end.

use std::net::UdpSocket;

use test_support::fixtures;
use test_support::golden;
use test_support::mock::{self, Tcp, Udp};

use crate::common::{dog, run, Run};

fn run_at(server: &str, args: &[&str]) -> Run {
    Run::of(dog().args(args).arg(server))
}

#[test]
fn a_successful_lookup_exits_0() {
    let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
    let run = run_at(&server.at(), &[ "-U", "--short", "a-example.lookup.dog" ]);
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (0, "10.20.30.40\n", ""));
}

#[test]
fn a_closed_tcp_connection_exits_1() {
    let server = mock::tcp(Tcp::CloseImmediately);
    let run = run_at(&server.at(), &[ "-T", "a-example.lookup.dog" ]);
    assert_eq!(run.status, 1);
    assert!(run.stderr.starts_with("Error [network]: "), "{}", run.stderr);
    assert_eq!(run.stdout, "");
}

#[test]
fn a_refused_udp_port_exits_1() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a UDP socket");
    let addr = socket.local_addr().expect("local address");
    drop(socket);

    let run = run_at(&format!("@{addr}"), &[ "-U", "a-example.lookup.dog" ]);
    assert_eq!(run.status, 1);
    assert_eq!(run.stderr, "Error [network]: Connection refused (os error 111)\n");
}

/// An answer with the right transaction ID that is cut short is the answer,
/// and it is broken.
#[test]
fn a_broken_answer_exits_1() {
    let broken = test_support::wire::truncate(&fixtures::response("a-example"), 20);
    let server = mock::udp(Udp::RawWithTxid(broken));
    let run = run_at(&server.at(), &[ "-U", "a-example.lookup.dog" ]);
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
               (1, "", "Error [protocol]: Malformed packet: insufficient data\n"));
}

#[test]
fn no_results_in_short_mode_exits_2() {
    let server = mock::udp(Udp::Replay(fixtures::response("nxdomain")));
    let run = run_at(&server.at(), &[ "-U", "--short", "non.existent" ]);
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (2, "", "No results\n"));
}

/// In short mode a network error with no answers exits 2, not 1: “no
/// results” takes precedence. This pins that existing behaviour.
#[test]
fn a_network_error_in_short_mode_exits_2() {
    let server = mock::tcp(Tcp::CloseImmediately);
    let run = run_at(&server.at(), &[ "-T", "--short", "a-example.lookup.dog" ]);
    assert_eq!(run.status, 2);
    assert!(run.stderr.starts_with("Error [network]: "), "{}", run.stderr);
    assert!(run.stderr.ends_with("No results\n"), "{}", run.stderr);
}

#[test]
fn invalid_options_exit_3() {
    let long_label = "a".repeat(256);
    let name_too_long = [ "a".repeat(63).as_str(); 4 ].join(".");
    let mut cases: Vec<(&str, Vec<&str>)> = vec![
        ("unknown-flag", vec![ "--wibble" ]),
        ("missing-argument", vec![ "example.com", "--txid" ]),
        ("invalid-tweak", vec![ "-Z", "aoeu", "example.com" ]),
        ("invalid-bufsize", vec![ "-Z", "bufsize=big", "example.com" ]),
        ("invalid-txid", vec![ "--txid", "zz", "example.com" ]),
        ("txid-too-big", vec![ "--txid", "65536", "example.com" ]),
        ("invalid-edns", vec![ "--edns", "wat", "example.com" ]),
        ("opt-query-free", vec![ "OPT", "example.com" ]),
        ("opt-query-named", vec![ "-t", "opt", "example.com" ]),
        ("invalid-type", vec![ "-t", "WIBBLE", "example.com" ]),
        ("invalid-class", vec![ "--class", "ZZ", "example.com" ]),
        ("label-too-long", vec![ long_label.as_str() ]),
        ("empty-label", vec![ "a..b" ]),
        ("empty-domain", vec![ "" ]),
        ("name-too-long", vec![ name_too_long.as_str() ]),
        ("control-character", vec![ "\x1b[31mred.example" ]),
        ("unknown-colour", vec![ "--colour=sometimes", "example.com" ]),
        ("tweak-needs-edns", vec![ "-Z", "do", "--edns", "disable", "example.com" ]),
    ];
    if cfg!(feature = "with_https") {
        cases.push(("https-without-url", vec![ "--https", "example.com" ]));
        cases.push(("https-url-line-break", vec![ "--https", "example.com", "@https://localhost/x\r\nX-Evil: 1" ]));
    }

    for (name, args) in cases {
        let run = run(&args);
        assert_eq!(run.status, 3, "{name}: {run:?}");
        golden::assert_golden(&format!("exit/{name}"), "txt", &run.transcript());
    }
}

/// When standard error could not be written to, dog panicked trying, which
/// aborted it, whatever it had been about to report. Now it exits as it
/// would have done.
#[cfg(target_os = "linux")]
#[test]
fn an_unwritable_standard_error_keeps_the_status() {
    use std::fs::OpenOptions;
    use std::process::{Command, Stdio};

    let status = |command: &mut Command| {
        let full = OpenOptions::new().write(true).open("/dev/full").expect("open /dev/full");
        command.stdout(Stdio::null()).stderr(full).status().expect("run dog").code().expect("dog exited with a status, not a signal")
    };

    assert_eq!(status(dog().arg("--wibble")), 3);
    assert_eq!(status(dog().arg("a..b")), 3);

    let closed = mock::tcp(Tcp::CloseImmediately);
    assert_eq!(status(dog().args([ "-T", "a-example.lookup.dog" ]).arg(closed.at())), 1);

    let nxdomain = mock::udp(Udp::Replay(fixtures::response("nxdomain")));
    assert_eq!(status(dog().args([ "-U", "--short", "non.existent" ]).arg(nxdomain.at())), 2);
    assert_eq!(status(dog().env("DOG_DEBUG", "trace").args([ "-U", "--short", "non.existent" ]).arg(nxdomain.at())), 2);
}

#[test]
fn no_domain_prints_the_usage_and_exits_3() {
    let run = run(&[ "--colour=never" ]);
    assert_eq!(run.status, 3);
    golden::assert_golden("exit/no-domain", "txt", &run.transcript());
}

/// The messages for protocols compiled out of dog, exactly as the original
/// feature checks in `xtests/features/` expect them.
#[cfg(not(feature = "with_tls"))]
#[test]
fn tls_without_the_feature_exits_3() {
    let run = run(&[ "--tls", "a.b.c.d" ]);
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
               (3, "", "dog: Cannot use '--tls': This version of dog has been compiled without TLS support\n"));
}

#[cfg(not(feature = "with_https"))]
#[test]
fn https_without_the_feature_exits_3() {
    let run = run(&[ "--https", "a.b.c.d", "@name.server" ]);
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
               (3, "", "dog: Cannot use '--https': This version of dog has been compiled without HTTPS support\n"));
}
