//! Help, version, timing and debug output.

use test_support::fixtures;
use test_support::golden;
use test_support::mock::{self, Udp};

use crate::common::{dog, run, Run};

/// Golden names are suffixed with the feature set, because the version
/// string lists features that were compiled out.
fn feature_suffix() -> &'static str {
    if cfg!(all(feature = "with_idna", feature = "with_tls", feature = "with_https")) {
        "default-features"
    }
    else {
        "no-default-features"
    }
}

#[test]
fn help_and_version() {
    let cases: &[(&str, &[&str])] = &[
        ("help-plain", &[ "--help", "--colour=never" ]),
        ("help-colour", &[ "--help", "--colour=always" ]),
        ("help-automatic", &[ "--help" ]),
        ("version-plain", &[ "--version", "--colour=never" ]),
        ("version-colour", &[ "--version", "--color=always" ]),
        ("version-short-flag", &[ "-v" ]),
    ];

    for (name, args) in cases {
        let run = run(args);
        assert_eq!(run.status, 0, "{name}");
        golden::assert_golden(&format!("meta/{name}.{}", feature_suffix()), "txt", &run.transcript());
    }
}

#[test]
fn timing_output() {
    let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
    let cases: &[(&str, &[&str])] = &[
        ("time-text", &[ "--time", "--colour=never" ]),
        ("time-json", &[ "--time", "--json" ]),
        ("seconds", &[ "--seconds", "--colour=never" ]),
        ("time-seconds", &[ "--time", "--seconds", "--colour=never" ]),
    ];

    for (name, args) in cases {
        let run = Run::of(dog().args([ "-U", "a-example.lookup.dog" ]).args(*args).arg(server.at()));
        assert_eq!(run.status, 0, "{name}");
        golden::assert_golden(&format!("meta/{name}"), "txt", &golden::normalise_timing(&run.transcript()));
    }
}

#[test]
fn no_color_turns_off_automatic_colour_only() {
    let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
    let automatic = Run::of(dog().env("NO_COLOR", "1").args([ "-U", "a-example.lookup.dog" ]).arg(server.at()));
    assert!(!automatic.stdout.contains('\x1b'), "{automatic:?}");

    let forced = Run::of(dog().env("NO_COLOR", "1").args([ "-U", "--colour=always", "a-example.lookup.dog" ]).arg(server.at()));
    assert!(forced.stdout.contains("\x1b[1;32mA\x1b[0m"), "{forced:?}");
}

/// The log goes to standard error, and when that is not a terminal, as
/// here, it has no escape codes in it; before, it always had.
#[test]
fn debug_logging_goes_to_stderr() {
    let server = mock::udp(Udp::Replay(fixtures::response("a-example")));

    let trace = Run::of(dog().env("DOG_DEBUG", "trace").args([ "-U", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((trace.status, trace.stdout.as_str()), (0, "10.20.30.40\n"));
    assert!(trace.stderr.lines().any(|line| line.starts_with("[TRACE dns::")), "{}", trace.stderr);
    assert!(trace.stderr.lines().any(|line| line.starts_with("[INFO dns_transport::")), "{}", trace.stderr);
    assert!(!trace.stderr.contains('\x1b'), "{}", trace.stderr);

    let debug = Run::of(dog().env("DOG_DEBUG", "1").args([ "-U", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert!(debug.stderr.lines().any(|line| line.starts_with("[DEBUG ")), "{}", debug.stderr);
    assert!(!debug.stderr.contains("TRACE"), "{}", debug.stderr);

    let empty = Run::of(dog().env("DOG_DEBUG", "").args([ "-U", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!(empty.stderr, "");
}
