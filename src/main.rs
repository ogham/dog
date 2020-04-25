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

#![deny(unsafe_code)]


use std::env;
use std::process::exit;
use std::time::Instant;

use log::*;

mod colours;
mod connect;
mod output;
mod requests;
mod resolve;
mod table;
mod txid;

mod options;
use self::options::*;


/// Configures logging, parses the command-line options, and handles any
/// errors before passing control over to the Dog type.
fn main() {
    configure_logger();

    match Options::getopts(env::args_os().skip(1)) {
        OptionsResult::Ok(options) => {
            info!("Running with options -> {:#?}", options);
            let dog = Dog::init(options);
            exit(dog.run());
        }

        OptionsResult::Help(help_reason, use_colours) => {
            if use_colours.should_use_colours() {
                print!("{}", include_str!(concat!(env!("OUT_DIR"), "/usage.pretty.txt")));
            }
            else {
                print!("{}", include_str!(concat!(env!("OUT_DIR"), "/usage.bland.txt")));
            }

            if help_reason == HelpReason::NoDomains {
                exit(exits::OPTIONS_ERROR);
            }
            else {
                exit(exits::SUCCESS);
            }
        }

        OptionsResult::Version(use_colours) => {
            if use_colours.should_use_colours() {
                print!("{}", include_str!(concat!(env!("OUT_DIR"), "/version.pretty.txt")));
            }
            else {
                print!("{}", include_str!(concat!(env!("OUT_DIR"), "/version.bland.txt")));
            }

            exit(exits::SUCCESS);
        }

        OptionsResult::InvalidOptionsFormat(oe) => {
            eprintln!("Invalid options: {:?}", oe);
            exit(exits::OPTIONS_ERROR);
        }

        OptionsResult::InvalidOptions(why) => {
            eprintln!("{}", why);
            exit(exits::OPTIONS_ERROR);
        }
    }
}


/// Checks the `DOG_DEBUG` environment variable, enabling debug logging if
/// it’s non-empty.
fn configure_logger() {
    let present = match env::var_os("DOG_DEBUG") {
        Some(debug)  => debug.len() > 0,
        None         => false,
    };

    let mut logs = env_logger::Builder::new();
    if present {
        let _ = logs.filter(None, log::LevelFilter::Debug);
    }
    else {
        let _ = logs.filter(None, log::LevelFilter::Off);
    }

    logs.init()
}

struct Dog {
    options: Options,
}

impl Dog {
    fn init(options: Options) -> Self {
        Self { options }
    }

    fn run(self) -> i32 {
        let Options { requests, format, measure_time } = self.options;
        let mut runtime = dns_transport::Runtime::new().expect("Failed to create runtime");
        let should_show_opt = requests.edns.should_show();

        let mut responses = Vec::new();
        let timer = if measure_time { Some(Instant::now()) } else { None };

        let mut errored = false;
        for (request, transport) in requests.generate() {
            let result = runtime.block_on(async { transport.send(&request).await });

            match result {
                Ok(mut response) => {
                    if ! should_show_opt {
                        response.answers.retain(dns::Answer::is_standard);
                        response.authorities.retain(dns::Answer::is_standard);
                        response.additionals.retain(dns::Answer::is_standard);
                    }

                    responses.push(response);
                }
                Err(e) => {
                    format.print_error(e);
                    errored = true;
                }
            }
        }

        let duration = timer.map(|t| t.elapsed());
        if format.print(responses, duration) {
            if errored {
                exits::NETWORK_ERROR
            }
            else {
                exits::SUCCESS
            }
        }
        else {
            exits::NO_SHORT_RESULTS
        }
    }
}


mod exits {
    #![allow(unused)]

    /// Exit code for when everything turns out OK.
    pub const SUCCESS: i32 = 0;

    /// Exit code for when there was at least one network error during execution.
    pub const NETWORK_ERROR: i32 = 1;

    /// Exit code for when there is no result from the server when running in
    /// short mode. This can be any received server error, not just NXDOMAIN.
    pub const NO_SHORT_RESULTS: i32 = 2;

    /// Exit code for when the command-line options are invalid.
    pub const OPTIONS_ERROR: i32 = 3;
}
