//! Stopping dog and continuing it, as ^Z and `fg` do, while it waits.
//!
//! A socket with a timeout set gives up its wait with “Interrupted system
//! call” when the process is continued, and dog used to report that as the
//! result of the query. Now it goes on waiting with the time that is left.

use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use test_support::fixtures;
use test_support::mock::{self, Tcp, Udp};

use crate::common::dog;

fn signal(pid: u32, name: &str) {
    let status = Command::new("kill").arg(format!("-{name}")).arg(pid.to_string()).status().expect("run kill");
    assert!(status.success(), "kill -{name} {pid}");
}

/// Runs dog, stops it partway through its wait, and continues it.
fn stopped_and_continued(command: &mut Command) -> (Option<i32>, String, String) {
    let child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("start dog");
    thread::sleep(Duration::from_millis(400));
    signal(child.id(), "STOP");
    thread::sleep(Duration::from_millis(300));
    signal(child.id(), "CONT");

    let output = child.wait_with_output().expect("wait for dog");
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).expect("dog’s output is UTF-8");
    (output.status.code(), text(output.stdout), text(output.stderr))
}

#[test]
fn a_wait_for_a_udp_answer() {
    let server = mock::udp(Udp::After(Duration::from_millis(1500), fixtures::response("a-example")));
    let result = stopped_and_continued(dog().args([ "-U", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!(result, (Some(0), "10.20.30.40\n".into(), String::new()));
}

#[test]
fn a_wait_for_a_slow_tcp_answer() {
    let server = mock::tcp(Tcp::Trickle(fixtures::response("a-example-tcp"), Duration::from_millis(20)));
    let result = stopped_and_continued(dog().args([ "-T", "--short", "a-example.lookup.dog" ]).arg(server.at()));
    assert_eq!(result, (Some(0), "10.20.30.40\n".into(), String::new()));
}
