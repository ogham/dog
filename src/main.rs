//! dog, the command-line DNS client.

#![warn(deprecated_in_future)]
#![warn(future_incompatible)]
#![warn(missing_copy_implementations)]
#![warn(missing_docs)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts, trivial_numeric_casts)]
#![warn(unused)]

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::enum_glob_use)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::wildcard_imports)]

#![deny(unsafe_code)]

use std::io::{self, Write};
use std::path::Path;
use std::time::Instant;

use log::*;

use dns::{Labels, Response};
use dns_transport::{Error as TransportError, Transport};

mod colours;
mod connect;
mod hints;
mod logger;
mod output;
mod requests;
mod resolve;
mod stderr;
mod system;
mod table;
mod txid;

mod options;
use self::options::*;

use self::output::{OutputFormat, UseColours};
use self::requests::RequestSet;
use self::system::SystemPaths;


/// Configures logging, parses the command-line options, and handles any
/// errors before passing control over to the Dog type.
fn main() {
    use std::env;
    use std::process::exit;

    logger::configure(env::var_os("DOG_DEBUG"));

    #[cfg(windows)]
    if let Err(e) = nu_ansi_term::enable_ansi_support() {
        warn!("Failed to enable ANSI support: {}", e);
    }

    match Options::getopts(env::args_os().skip(1)) {
        OptionsResult::Ok(options) => {
            info!("Running with options -> {options:#?}");
            exit(run(options, &SystemPaths::system()));
        }

        OptionsResult::Help(help_reason, use_colours) => {
            let usage = pick(use_colours, include_str!(concat!(env!("OUT_DIR"), "/usage.pretty.txt")),
                                          include_str!(concat!(env!("OUT_DIR"), "/usage.bland.txt")));
            let status = if help_reason == HelpReason::NoDomains { exits::OPTIONS_ERROR } else { exits::SUCCESS };
            exit(emit(usage, status));
        }

        OptionsResult::Version(use_colours) => {
            let version = pick(use_colours, include_str!(concat!(env!("OUT_DIR"), "/version.pretty.txt")),
                                            include_str!(concat!(env!("OUT_DIR"), "/version.bland.txt")));
            exit(emit(version, exits::SUCCESS));
        }

        OptionsResult::InvalidOptionsFormat(oe) => {
            stderr::line(format_args!("dog: Invalid options: {oe}"));
            exit(exits::OPTIONS_ERROR);
        }

        OptionsResult::InvalidOptions(why) => {
            stderr::line(format_args!("dog: {}", why.report()));
            exit(exits::OPTIONS_ERROR);
        }
    }
}

/// Picks the coloured or the plain version of some text.
fn pick(use_colours: UseColours, pretty: &'static str, bland: &'static str) -> &'static str {
    if use_colours.should_use_colours() { pretty } else { bland }
}

/// Writes text to standard output, and returns the status to exit with.
fn emit(text: &str, status: i32) -> i32 {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => status,
        Err(e) => output_failure(&e, status),
    }
}

/// The status to exit with when standard output could not be written to.
/// If nothing is reading it any more, as when dog’s output is piped into
/// `head`, there is nothing wrong, and dog finishes as it would have done;
/// any other failure is reported.
fn output_failure(error: &io::Error, status_otherwise: i32) -> i32 {
    if error.kind() == io::ErrorKind::BrokenPipe {
        debug!("Standard output was closed: {error}");
        status_otherwise
    }
    else {
        stderr::line(format_args!("dog: Cannot write output: {error}"));
        exits::SYSTEM_ERROR
    }
}


/// Runs dog with some options, reading the system’s configuration from the
/// given paths, and returns the status to exit with.
fn run(options: Options, paths: &SystemPaths) -> i32 {
    let Options { requests, format, measure_time } = options;
    let timer = measure_time.then(Instant::now);

    warn_about_local_hosts(&requests.inputs.domains, &paths.hosts);

    let show_opt = requests.edns.should_show();
    let request_sets = match requests.generate(paths) {
        Ok(sets) => sets,
        Err(e) => {
            stderr::line(format_args!("Unable to obtain resolver: {e}"));
            return exits::SYSTEM_ERROR;
        }
    };

    let (responses, errored) = send_all(request_sets, format, show_opt);
    let duration = timer.map(|t| t.elapsed());
    match format.print(responses, duration) {
        Ok(printed) => exit_code(printed, errored),
        Err(e)      => output_failure(&e, exit_code(true, errored)),
    }
}

/// Warns about any queried name that the hosts file also lists, because
/// the system will use that entry instead of whatever DNS says.
fn warn_about_local_hosts(domains: &[Labels], hosts_path: &Path) {
    let local_hosts = hints::LocalHosts::load(hosts_path).unwrap_or_else(|e| {
        warn!("Error loading local host hints: {e}");
        hints::LocalHosts::default()
    });

    for domain in domains {
        if local_hosts.contains(domain) {
            stderr::line(format_args!("warning: domain '{domain}' also exists in hosts file"));
        }
    }
}

/// Sends every set of requests, printing each transport error as it
/// happens. Returns the responses, and whether any transport failed.
fn send_all(request_sets: Vec<RequestSet>, format: OutputFormat, show_opt: bool) -> (Vec<Response>, bool) {
    let mut responses = Vec::new();
    let mut errored = false;

    for (transport, requests) in request_sets {
        let Some(result) = send_until_answered(transport.as_ref(), requests) else { continue };
        match result {
            Ok(mut response) => {
                warn_if_truncated(&response);
                if ! show_opt {
                    strip_pseudo_records(&mut response);
                }
                responses.push(response);
            }
            Err(e) => {
                format.print_error(e);
                errored = true;
            }
        }
    }

    (responses, errored)
}

/// Sends the requests in turn, one for each name in the search list, until
/// one is answered without an error code; the last is kept whatever its
/// code. A transport error stops the search. Returns `None` only when there
/// are no requests at all.
fn send_until_answered(transport: &dyn Transport, requests: Vec<dns::Request>) -> Option<Result<Response, TransportError>> {
    let last = requests.len().saturating_sub(1);
    for (i, request) in requests.into_iter().enumerate() {
        match transport.send(&request) {
            Ok(response) if response.flags.error_code.is_some() && i != last => {}
            result => return Some(result),
        }
    }

    None
}

/// Warns that a response was cut short. Only a response over UDP can be, and
/// the automatic transport asks again over TCP when one is, so this is seen
/// when UDP alone was asked for; before, dog printed what there was, or
/// nothing at all, without a word.
fn warn_if_truncated(response: &Response) {
    if response.flags.truncated {
        stderr::line(format_args!("warning: the response was truncated, so records may be missing; use --tcp to get them all"));
    }
}

/// Removes OPT pseudo-records, which are only shown when asked for.
fn strip_pseudo_records(response: &mut Response) {
    response.answers.retain(dns::Answer::is_standard);
    response.authorities.retain(dns::Answer::is_standard);
    response.additionals.retain(dns::Answer::is_standard);
}

/// The status to exit with, given whether any results were printed and
/// whether any transport failed. Having no results in short mode takes
/// precedence over a network error.
fn exit_code(printed: bool, errored: bool) -> i32 {
    match (printed, errored) {
        (false, _)     => exits::NO_SHORT_RESULTS,
        (true, true)   => exits::NETWORK_ERROR,
        (true, false)  => exits::SUCCESS,
    }
}


/// The possible status numbers dog can exit with.
mod exits {

    /// Exit code for when everything turns out OK.
    pub const SUCCESS: i32 = 0;

    /// Exit code for when there was at least one network error during execution.
    pub const NETWORK_ERROR: i32 = 1;

    /// Exit code for when there is no result from the server when running in
    /// short mode. This can be any received server error, not just `NXDOMAIN`.
    pub const NO_SHORT_RESULTS: i32 = 2;

    /// Exit code for when the command-line options are invalid.
    pub const OPTIONS_ERROR: i32 = 3;

    /// Exit code for when the system network configuration could not be
    /// determined, or the output could not be written.
    pub const SYSTEM_ERROR: i32 = 4;
}


#[cfg(test)]
mod test {
    use super::*;
    use std::cell::RefCell;
    use test_support::fixtures;
    use test_support::mock::{self, Tcp, Udp};

    fn paths(resolv_conf: &str) -> SystemPaths {
        let etc = fixtures::root().join("etc");
        SystemPaths { hosts: etc.join("hosts.debian"), resolv_conf: etc.join(resolv_conf) }
    }

    fn options(args: &[&str]) -> Options {
        match Options::getopts(args) { OptionsResult::Ok(options) => options, other => panic!("{other:?}") }
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(true, false), exits::SUCCESS);
        assert_eq!(exit_code(true, true), exits::NETWORK_ERROR);
        assert_eq!(exit_code(false, false), exits::NO_SHORT_RESULTS);
        assert_eq!(exit_code(false, true), exits::NO_SHORT_RESULTS);
    }

    /// A closed pipe is how `head` tells dog it has seen enough; anything
    /// else going wrong with the output is a failure.
    #[test]
    fn output_failures() {
        assert_eq!(output_failure(&io::ErrorKind::BrokenPipe.into(), exits::NETWORK_ERROR), exits::NETWORK_ERROR);
        assert_eq!(output_failure(&io::Error::other("disk full"), exits::SUCCESS), exits::SYSTEM_ERROR);
    }

    #[test]
    fn picking_text() {
        assert_eq!(pick(UseColours::Always, "pretty", "bland"), "pretty");
        assert_eq!(pick(UseColours::Never, "pretty", "bland"), "bland");
    }

    /// Without a nameserver on the command line, dog needs the system’s;
    /// failing to find one is a system error, not a network error.
    #[test]
    fn no_system_nameserver_is_a_system_error() {
        assert_eq!(run(options(&[ "example.com" ]), &paths("hosts.docker")), exits::SYSTEM_ERROR);
        assert_eq!(run(options(&[ "example.com" ]), &paths("no-such-file")), exits::SYSTEM_ERROR);
    }

    /// A missing hosts file only means there is nothing to warn about.
    #[test]
    fn a_missing_hosts_file_is_not_an_error() {
        let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
        let mut paths = paths("no-such-file");
        paths.hosts = fixtures::root().join("etc").join("no-such-hosts");
        assert_eq!(run(options(&[ "-U", "--short", "a-example.lookup.dog", &server.at() ]), &paths), exits::SUCCESS);
    }

    /// dog warns about a name the hosts file lists, but still asks DNS.
    #[test]
    fn a_name_in_the_hosts_file_is_still_looked_up() {
        let hosts = std::env::temp_dir().join(format!("dog-test-hosts-{}", std::process::id()));
        std::fs::write(&hosts, "192.0.2.1 a-example.lookup.dog\n").unwrap();

        let server = mock::udp(Udp::Replay(fixtures::response("a-example")));
        let mut paths = paths("no-such-file");
        paths.hosts = hosts.clone();
        let status = run(options(&[ "-U", "--time", "a-example.lookup.dog", &server.at() ]), &paths);
        std::fs::remove_file(&hosts).unwrap();

        assert_eq!(status, exits::SUCCESS);
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn a_transport_error_is_a_network_error() {
        let server = mock::tcp(Tcp::CloseImmediately);
        assert_eq!(run(options(&[ "-T", "--json", "a-example.lookup.dog", &server.at() ]), &paths("no-such-file")), exits::NETWORK_ERROR);
    }

    /// A transport that answers each request with the next of some real
    /// captured responses.
    struct Replay(RefCell<Vec<&'static str>>);

    impl Transport for Replay {
        fn send(&self, _request: &dns::Request) -> Result<Response, TransportError> {
            let name = self.0.borrow_mut().remove(0);
            Ok(Response::from_bytes(&fixtures::response(name)).expect("a captured response parses"))
        }
    }

    fn requests(count: usize) -> Vec<dns::Request> {
        (0 .. count).map(|_| dns::Request {
            transaction_id: 0,
            flags: dns::Flags::query(),
            query: dns::Query { qname: Labels::encode("printer").unwrap(), qclass: dns::QClass::IN, qtype: dns::record::RecordType::A },
            additional: None,
        }).collect()
    }

    #[test]
    fn the_search_stops_at_the_first_name_answered_without_an_error() {
        let transport = Replay(RefCell::new(vec![ "nxdomain", "a-example", "aaaa-example" ]));
        let response = send_until_answered(&transport, requests(3)).unwrap().unwrap();
        assert_eq!(response.flags.error_code, None);
        assert_eq!(*transport.0.borrow(), [ "aaaa-example" ]);
    }

    #[test]
    fn the_last_name_is_kept_even_with_an_error() {
        let transport = Replay(RefCell::new(vec![ "nxdomain", "nxdomain" ]));
        let response = send_until_answered(&transport, requests(2)).unwrap().unwrap();
        assert_eq!(response.flags.error_code, Some(dns::ErrorCode::NXDomain));
    }

    #[test]
    fn no_requests_means_no_response() {
        assert!(send_until_answered(&Replay(RefCell::new(Vec::new())), Vec::new()).is_none());
    }

    #[test]
    fn pseudo_records_are_stripped() {
        let mut response = Response::from_bytes(&fixtures::response("a-example")).unwrap();
        assert_eq!(response.additionals.len(), 1);
        strip_pseudo_records(&mut response);
        assert!(response.additionals.is_empty());
        assert_eq!(response.answers.len(), 1);
    }
}
