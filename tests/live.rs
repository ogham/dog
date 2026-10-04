//! Tests against real servers on the internet: public resolvers over every
//! transport, badssl.com's broken certificates, and httpbin's HTTP errors.
//!
//! They check what the offline suite cannot — that dog interoperates with
//! real nameservers, and that the system OpenSSL rejects bad certificates —
//! so they are `#[ignore]`d, and the normal suite never touches the network.
//! Run them with `just test-live`.
//!
//! The expected records are the `lookup.dog` test zone as served in
//! September 2026.

use std::process::Command;

/// Each record in the `lookup.dog` test zone, with its `--short` output.
const RECORDS: &[(&str, &str, &[&str])] = &[
    ("A",     "a-example.lookup.dog",     &[ "10.20.30.40" ]),
    ("AAAA",  "aaaa-example.lookup.dog",  &[ "::1" ]),
    ("CAA",   "caa-example.lookup.dog",   &[ r#""issue" "some.certificate.authority" (non-critical)"# ]),
    ("CNAME", "cname-example.lookup.dog", &[ r#""dns.lookup.dog.""# ]),
    ("HINFO", "hinfo-example.lookup.dog", &[ r#""some-kinda-cpu" "some-kinda-os""# ]),
    ("MX",    "mx-example.lookup.dog",    &[ r#"10 "some.mail.server.""# ]),
    ("NS",    "lookup.dog",               &[ r#""ns1.dnsimple.com.""#, r#""ns2.dnsimple.com.""#, r#""ns3.dnsimple.com.""#, r#""ns4.dnsimple.com.""# ]),
    ("SOA",   "lookup.dog",               &[ r#""ns1.dnsimple.com." "admin.dnsimple.com." 1564273569 1d0h00m00s 2h00m00s 7d0h00m00s 5m00s"# ]),
    ("SRV",   "srv-example.lookup.dog",   &[ r#"10 20 "dns.lookup.dog.":5000"# ]),
    ("TXT",   "txt-example.lookup.dog",   &[ r#""Cache Invalidation and Naming Things""# ]),
];

/// What one run of dog produced.
struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

/// Runs dog with the environment variables that change its behaviour
/// removed, so the system's own CA store is the one in use.
fn dog(args: &[&str]) -> Run {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dog"));
    for variable in [ "DOG_DEBUG", "NO_COLOR", "SSL_CERT_FILE", "SSL_CERT_DIR" ] {
        command.env_remove(variable);
    }
    let output = command.args(args).output().expect("start dog");
    Run {
        status: output.status.code().expect("dog exited with a status, not a signal"),
        stdout: String::from_utf8(output.stdout).expect("dog's stdout is UTF-8"),
        stderr: String::from_utf8(output.stderr).expect("dog's stderr is UTF-8"),
    }
}

/// Every record in the test zone comes back in full from the nameserver
/// over the transport, and a name that does not exist has no results.
/// Resolvers may rotate the order of a record set, so lines are compared
/// sorted.
fn every_record_type(nameserver: &str, transport: &[&str]) {
    for (qtype, name, expected) in RECORDS {
        let run = dog(&[ &[ *qtype, *name, nameserver, "--short" ], transport ].concat());
        let mut lines = run.stdout.lines().collect::<Vec<_>>();
        lines.sort_unstable();
        assert_eq!((run.status, lines.as_slice(), run.stderr.as_str()), (0, *expected, ""), "{qtype} {name}");
    }

    let run = dog(&[ &[ "A", "non.existent", nameserver, "--short" ], transport ].concat());
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()), (2, "", "No results\n"));
}

#[test]
#[ignore = "uses the internet"]
fn cloudflare_over_udp() {
    every_record_type("@1.1.1.1", &[ "--udp" ]);
}

#[test]
#[ignore = "uses the internet"]
fn cloudflare_over_tcp() {
    every_record_type("@1.1.1.1", &[ "--tcp" ]);
}

#[test]
#[ignore = "uses the internet"]
fn google_over_udp() {
    every_record_type("@8.8.8.8", &[]);
}

#[cfg(feature = "with_tls")]
#[test]
#[ignore = "uses the internet"]
fn cloudflare_over_tls() {
    every_record_type("@1.1.1.1", &[ "--tls" ]);
}

#[cfg(feature = "with_https")]
#[test]
#[ignore = "uses the internet"]
fn cloudflare_over_https() {
    every_record_type("@https://cloudflare-dns.com/dns-query", &[ "--https" ]);
}

#[cfg(feature = "with_https")]
#[test]
#[ignore = "uses the internet"]
fn google_over_https() {
    every_record_type("@https://dns.google/dns-query", &[ "--https" ]);
}

/// Quad9 speaks only HTTP/2, and answered dog’s HTTP/1.1 with “505 HTTP
/// Version Not Supported” until dog offered HTTP/2.
#[cfg(feature = "with_https")]
#[test]
#[ignore = "uses the internet"]
fn quad9_over_https() {
    every_record_type("@https://dns.quad9.net/dns-query", &[ "--https" ]);
}

/// The JSON output is valid, and holds every answer with the queried type;
/// a name that does not exist is an NXDOMAIN with no answers.
#[test]
#[ignore = "uses the internet"]
fn json_output() {
    for (qtype, name, expected) in RECORDS {
        let run = dog(&[ qtype, name, "@1.1.1.1", "--json" ]);
        assert_eq!((run.status, run.stderr.as_str()), (0, ""), "{qtype} {name}");

        let json: serde_json::Value = serde_json::from_str(&run.stdout).expect("dog's output is JSON");
        let answers = json["responses"][0]["answers"].as_array().expect("an answers array");
        assert_eq!(answers.len(), expected.len(), "{qtype} {name}: {answers:?}");
        assert!(answers.iter().all(|answer| answer["type"] == *qtype), "{qtype} {name}: {answers:?}");
    }

    let run = dog(&[ "A", "non.existent", "@1.1.1.1", "--json" ]);
    let json: serde_json::Value = serde_json::from_str(&run.stdout).expect("dog's output is JSON");
    assert_eq!(json["responses"][0]["flags"]["rcode"], "NXDOMAIN");
    assert_eq!(json["responses"][0]["answers"], serde_json::json!([]));
}

/// With no arguments but a name, dog asks the system's nameserver for A
/// records and prints a table, in colour when asked.
#[test]
#[ignore = "uses the internet"]
fn the_system_nameserver_and_the_default_table() {
    for args in [ &[ "dns.google" ][..], &[ "dns.google", "-U" ], &[ "A", "dns.google", "--colour=never" ] ] {
        let run = dog(args);
        assert_eq!((run.status, run.stderr.as_str()), (0, ""), "{args:?}");
        assert!(run.stdout.lines().all(|line| line.starts_with("A dns.google. ")), "{args:?}\n{}", run.stdout);
    }

    let run = dog(&[ "dns.google", "--colour=always" ]);
    assert!(run.stdout.lines().all(|line| line.starts_with("\x1b[1;32mA\x1b[0m \x1b[1;34mdns.google.\x1b[0m ")), "{}", run.stdout);

    let run = dog(&[ "A", "dns.google", "--time" ]);
    assert!(run.stdout.lines().last().is_some_and(|line| line.starts_with("Ran in ")), "{}", run.stdout);
}

/// A nameserver given by a name that does not resolve (`.invalid` never
/// does, by RFC 6761) is a network error, still reporting the time taken.
#[test]
#[ignore = "uses the internet"]
fn a_nameserver_name_that_does_not_resolve() {
    let run = dog(&[ "A", "dns.google", "@nameserver.invalid", "--time" ]);
    assert_eq!(run.status, 1);
    assert!(run.stdout.starts_with("Ran in "), "{}", run.stdout);
    assert!(run.stderr.starts_with("Error [network]: "), "{}", run.stderr);
}

/// OpenSSL refuses each of badssl.com's bad certificates, with its own
/// reason for each.
#[cfg(feature = "with_https")]
#[test]
#[ignore = "uses the internet"]
fn untrusted_certificates_are_refused() {
    let hosts = [
        ("expired",        "(certificate has expired)"),
        ("wrong.host",     "(hostname mismatch)"),
        ("self-signed",    "(self-signed certificate)"),
        ("untrusted-root", "(self-signed certificate in certificate chain)"),
        ("superfish",      "(unable to get local issuer certificate)"),
    ];

    for (host, reason) in hosts {
        let run = dog(&[ "--https", &format!("@https://{host}.badssl.com/"), "lookup.dog" ]);
        assert_eq!((run.status, run.stdout.as_str()), (1, ""), "{host}");
        assert!(run.stderr.starts_with("Error [tls]: "), "{host}: {}", run.stderr);
        assert!(run.stderr.contains("certificate verify failed"), "{host}: {}", run.stderr);
        assert!(run.stderr.trim_end().ends_with(reason), "{host}: {}", run.stderr);
    }
}

/// OpenSSL will not negotiate the null or RC4 ciphers these servers insist
/// on, so the handshake fails.
#[cfg(feature = "with_https")]
#[test]
#[ignore = "uses the internet"]
fn weak_ciphers_are_refused() {
    for host in [ "null", "rc4-md5" ] {
        let run = dog(&[ "--https", &format!("@https://{host}.badssl.com/"), "lookup.dog" ]);
        assert_eq!((run.status, run.stdout.as_str()), (1, ""), "{host}");
        assert!(run.stderr.starts_with("Error [tls]: "), "{host}: {}", run.stderr);
        assert!(run.stderr.contains("handshake failure"), "{host}: {}", run.stderr);
    }
}

/// A known limitation, pinned so that a change is noticed: OpenSSL, through
/// native-tls, does not check certificate revocation. The handshake with
/// the revoked certificate succeeds, and it is badssl.com's web server,
/// not TLS, that rejects the query.
#[cfg(feature = "with_https")]
#[test]
#[ignore = "uses the internet"]
fn revoked_certificates_are_not_checked() {
    let run = dog(&[ "--https", "@https://revoked.badssl.com/", "lookup.dog" ]);
    assert_eq!((run.status, run.stdout.as_str()), (1, ""));
    assert!(run.stderr.starts_with("Error [http]: "), "{}", run.stderr);
}

/// A DoH server's HTTP error is reported with its status, and a 200 with an
/// empty body is a malformed DNS packet. httpbin chooses HTTP/2 when it is
/// offered, and HTTP/2 has no reason phrases, so there is only the status.
#[cfg(feature = "with_https")]
#[test]
#[ignore = "uses the internet"]
fn http_errors_from_a_real_server() {
    let run = dog(&[ "--https", "@https://eu.httpbin.org/status/500", "lookup.dog" ]);
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
               (1, "", "Error [http]: Nameserver returned HTTP 500\n"));

    let run = dog(&[ "--https", "@https://eu.httpbin.org/status/200", "lookup.dog" ]);
    assert_eq!((run.status, run.stdout.as_str(), run.stderr.as_str()),
               (1, "", "Error [protocol]: Malformed packet: insufficient data\n"));
}
