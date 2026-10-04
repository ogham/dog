//! How dog renders every captured response, in every output mode.

use std::thread;

use test_support::fixtures::{self, Row};
use test_support::golden;
use test_support::mock::{self, Server, Tcp, Udp};

use crate::common::{dog, question_args, Run};

/// The output modes each response is rendered in.
const MODES: &[&[&str]] = &[
    &[ "--colour=never" ],
    &[ "--colour=always" ],
    &[ "--short" ],
    &[ "--json" ],
    &[ "--edns", "show", "--colour=never" ],
];

fn serve(row: &Row) -> (Server, &'static str) {
    let response = fixtures::response(&row.name);
    if row.transport == "tcp" {
        (mock::tcp(Tcp::Replay(response)), "-T")
    }
    else {
        (mock::udp(Udp::Replay(response)), "-U")
    }
}

fn render(row: &Row) -> String {
    let (server, transport) = serve(row);
    let mut transcript = String::new();
    for mode in MODES {
        let mut args = vec![ transport.to_owned() ];
        args.extend(mode.iter().map(|arg| (*arg).to_owned()));
        args.extend(question_args(row));

        let run = Run::of(dog().args(&args).arg(server.at()));
        transcript.push_str(&format!("== dog {}\n{}", args.join(" "), run.transcript()));
    }
    transcript
}

#[test]
fn every_captured_response_renders_as_before() {
    let rows = fixtures::dns_rows();
    assert!(rows.len() > 60, "expected every captured fixture in the manifest, found {}", rows.len());

    let transcripts = thread::scope(|scope| {
        let handles = rows.iter().map(|row| scope.spawn(move || render(row))).collect::<Vec<_>>();
        handles.into_iter().map(|handle| handle.join().expect("rendering a fixture")).collect::<Vec<_>>()
    });

    for (row, transcript) in rows.iter().zip(transcripts) {
        golden::assert_golden(&format!("records/{}", row.name), "txt", &transcript);
    }
}
