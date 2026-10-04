//! Writing into a pipe that nothing reads any more, as when dog’s output
//! goes to `head`. dog used to panic there, which release builds turn into
//! an abort.

use std::io;
use std::process::Stdio;

use test_support::fixtures;
use test_support::mock::{self, Udp};

use crate::common::dog;

/// Runs dog with its standard output going into a pipe whose reading end
/// is already closed, and returns its status and standard error.
fn run_into_a_closed_pipe(args: &[&str]) -> (i32, String) {
    let (reader, writer) = io::pipe().expect("create a pipe");
    drop(reader);

    let output = dog().args(args).stdout(writer).stderr(Stdio::piped()).output().expect("run dog");
    let status = output.status.code().expect("dog exited with a status, not a signal");
    (status, String::from_utf8(output.stderr).expect("stderr is UTF-8"))
}

#[test]
fn help() {
    assert_eq!(run_into_a_closed_pipe(&[ "--help" ]), (0, String::new()));
}

#[test]
fn version() {
    assert_eq!(run_into_a_closed_pipe(&[ "--version" ]), (0, String::new()));
}

#[test]
fn usage_after_no_domain_keeps_its_status() {
    assert_eq!(run_into_a_closed_pipe(&[]), (3, String::new()));
}

#[test]
fn results_in_every_format() {
    let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
    for format in [ "--colour=never", "--short", "--json" ] {
        let at = server.at();
        assert_eq!(run_into_a_closed_pipe(&[ "-U", format, "a-example.lookup.dog", &at ]), (0, String::new()), "{format}");
    }
}
