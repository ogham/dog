//! Running dog and describing what it did.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use test_support::fixtures::Row;

/// How long any single run of dog may take before the test fails. Far above
/// anything a loopback exchange needs; it only exists so that a hang fails
/// the suite rather than stopping it.
const LIMIT: Duration = Duration::from_secs(30);

/// A `dog` command, with the environment variables that change its
/// behaviour removed.
pub fn dog() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dog"));
    for variable in [ "DOG_DEBUG", "NO_COLOR", "SSL_CERT_FILE", "SSL_CERT_DIR" ] {
        command.env_remove(variable);
    }
    command
}

/// What one run of dog produced.
#[derive(Debug)]
pub struct Run {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Run {

    /// Runs the command to completion and collects its output.
    ///
    /// # Panics
    ///
    /// Panics if dog cannot start, takes longer than the limit, is killed by
    /// a signal, or writes output that is not UTF-8.
    pub fn of(command: &mut Command) -> Self {
        let mut child = command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .spawn().expect("start dog");
        let stdout = read_in_background(child.stdout.take().expect("stdout is piped"));
        let stderr = read_in_background(child.stderr.take().expect("stderr is piped"));
        let status = wait_limited(&mut child);
        Self {
            status,
            stdout: stdout.join().expect("read dog's stdout"),
            stderr: stderr.join().expect("read dog's stderr"),
        }
    }

    /// The run rendered for a golden file.
    pub fn transcript(&self) -> String {
        format!("-- status {}\n-- stdout\n{}-- stderr\n{}", self.status, self.stdout, self.stderr)
    }
}

fn read_in_background(mut pipe: impl Read + Send + 'static) -> JoinHandle<String> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes).expect("read from dog");
        String::from_utf8(bytes).expect("dog's output is UTF-8")
    })
}

fn wait_limited(child: &mut Child) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("wait for dog") {
            return status.code().expect("dog exited with a status, not a signal");
        }
        if start.elapsed() > LIMIT {
            child.kill().expect("kill dog");
            panic!("dog did not finish within {LIMIT:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// Runs dog with the given arguments.
pub fn run(args: &[&str]) -> Run {
    Run::of(dog().args(args))
}

/// The record type numbers dog is asked for, by the names used in the
/// fixture manifest. Numbers are passed so that the rendering tests do not
/// depend on which type names dog knows.
const QTYPE_NUMBERS: &[(&str, u16)] = &[
    ("A", 1), ("NS", 2), ("CNAME", 5), ("SOA", 6), ("PTR", 12), ("HINFO", 13),
    ("MX", 15), ("TXT", 16), ("AAAA", 28), ("LOC", 29), ("SRV", 33), ("NAPTR", 35),
    ("DS", 43), ("SSHFP", 44), ("RRSIG", 46), ("NSEC", 47), ("DNSKEY", 48),
    ("TLSA", 52), ("OPENPGPKEY", 61), ("HTTPS", 65), ("EUI48", 108), ("EUI64", 109),
    ("URI", 256), ("CAA", 257),
];

fn type_number(qtype: &str) -> u16 {
    if let Some(number) = qtype.strip_prefix("TYPE") {
        return number.parse().expect("TYPEnnn has a number");
    }
    QTYPE_NUMBERS.iter().find(|(name, _)| *name == qtype)
        .unwrap_or_else(|| panic!("no type number for {qtype}")).1
}

/// The arguments that make dog ask the question a fixture was captured with.
pub fn question_args(row: &Row) -> Vec<String> {
    let mut args = vec![
        "-q".into(), row.qname.clone(),
        "-t".into(), type_number(&row.qtype).to_string(),
        "--class".into(), row.qclass.clone(),
    ];

    if row.knob("edns") == Some("0") {
        args.extend([ "--edns".into(), "disable".into() ]);
    }
    if row.knob("do") == Some("1") {
        args.extend([ "-Z".into(), "do".into() ]);
    }
    if let Some(size) = row.knob("bufsize").filter(|size| *size != "512") {
        args.extend([ "-Z".into(), format!("bufsize={size}") ]);
    }
    args
}

/// Whether dog can send exactly the query a fixture was captured with. It
/// cannot clear the RD bit, set an opcode or EDNS version, or ask two
/// questions at once.
pub fn dog_can_send(row: &Row) -> bool {
    [ ("rd", "1"), ("opcode", "0"), ("qdcount", "1"), ("version", "0") ].iter()
        .all(|(knob, value)| row.knob(knob) == Some(value))
}
