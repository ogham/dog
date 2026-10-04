//! Nothing a server sends reaches the terminal as a control character.
//!
//! Names used to be printed exactly as they came, so a hostile server could
//! set the terminal’s title, clear its screen, or forge extra rows in the
//! table. Each response here is a real one with a name changed.

use test_support::fixtures;
use test_support::mock::{self, Tcp, Udp};
use test_support::wire;

use crate::common::{dog, Run};

/// A name in wire format, from its labels.
fn encoded(labels: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for label in labels {
        bytes.push(u8::try_from(label.len()).expect("a label fits its length byte"));
        bytes.extend_from_slice(label);
    }
    bytes.push(0);
    bytes
}

/// The real answer for `a-example.lookup.dog`, with its A record’s owner
/// name, a pointer to the question, replaced by this name written out.
fn answer_owned_by(labels: &[&[u8]]) -> Vec<u8> {
    let response = fixtures::response("a-example");
    let span = wire::first_rr(&response, 1);
    assert_eq!(response[span.name_at] & 0xC0, 0xC0, "the owner name is a pointer");
    wire::splice(&response, span.name_at .. span.name_at + 2, &encoded(labels))
}

/// The real answer for `a-example.lookup.dog`, with its question changed to
/// this name, so that it answers some other question.
fn question_changed_to(labels: &[&[u8]]) -> Vec<u8> {
    let response = fixtures::response("a-example-tcp");
    let question_name_end = wire::question_end(&response) - 4;
    wire::splice(&response, wire::HEADER_LEN .. question_name_end, &encoded(labels))
}

fn run_against(response: Vec<u8>, args: &[&str]) -> Run {
    let server = mock::udp(Udp::Replay(response));
    Run::of(dog().args([ "-U" ]).args(args).arg("a-example.lookup.dog").arg(server.at()))
}

const TITLE: &[u8] = b"\x1b]0;pwned\x07";

#[test]
fn escape_sequences_in_names_are_escaped() {
    let response = answer_owned_by(&[ TITLE, b"evil" ]);

    let plain = run_against(response.clone(), &[ "--colour=never" ]);
    assert_eq!(plain.status, 0);
    assert!(plain.stdout.contains(r"\027]0;pwned\007.evil."), "{plain:?}");
    assert!(!plain.stdout.contains('\x1b') && !plain.stdout.contains('\x07'), "{plain:?}");

    let coloured = run_against(response.clone(), &[ "--colour=always" ]);
    assert!(coloured.stdout.contains(r"\027]0;pwned\007.evil."), "{coloured:?}");
    assert!(!coloured.stdout.contains("\x1b]") && !coloured.stdout.contains('\x07'), "{coloured:?}");

    let json = run_against(response, &[ "--json" ]);
    let value: serde_json::Value = serde_json::from_str(&json.stdout).expect("dog’s output is JSON");
    assert_eq!(value["responses"][0]["answers"][0]["name"], r"\027]0;pwned\007.evil.");
}

#[test]
fn line_breaks_in_names_cannot_forge_rows() {
    let run = run_against(answer_owned_by(&[ b"line\nA forged 1.2.3.4", b"example" ]), &[ "--colour=never" ]);
    assert_eq!(run.status, 0);
    assert_eq!(run.stdout.lines().count(), 1, "{run:?}");
    assert!(run.stdout.contains(r"line\010A\032forged\0321\.2\.3\.4.example."), "{run:?}");
}

/// The question a response repeats is echoed in the error when it is not
/// the one that was asked.
#[test]
fn names_in_errors_are_escaped() {
    let server = mock::tcp(Tcp::Replay(question_changed_to(&[ TITLE, b"evil" ])));
    let run = Run::of(dog().args([ "-T", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!((run.status, run.stderr.as_str()),
               (1, "Error [protocol]: Response is for '\\027]0;pwned\\007.evil. A IN', expected 'a-example.lookup.dog. A IN'\n"));
}
