//! Debug error logging.

use std::ffi::OsStr;
use std::io::{self, IsTerminal, Write};

use nu_ansi_term::{Color, AnsiString};

use crate::colours;
use crate::stderr;


/// Sets the internal logger, changing the log level based on the value of an
/// environment variable. The log is coloured only when standard error goes
/// to a terminal that wants colours.
pub fn configure<T: AsRef<OsStr>>(ev: Option<T>) {
    let Some(ev) = ev else { return };

    let env_var = ev.as_ref();
    if env_var.is_empty() {
        return;
    }

    if env_var == "trace" {
        log::set_max_level(log::LevelFilter::Trace);
    }
    else {
        log::set_max_level(log::LevelFilter::Debug);
    }

    let logger = if colours::terminal_wants_colour(io::stderr().is_terminal()) { &COLOURED } else { &PLAIN };
    if let Err(e) = log::set_logger(logger) {
        stderr::line(format_args!("Failed to initialise logger: {e}"));
    }
}


#[derive(Debug)]
struct Logger {
    colour: bool,
}

static COLOURED: Logger = Logger { colour: true };
static PLAIN: Logger = Logger { colour: false };

impl Logger {

    /// The line written for a log record.
    fn line(&self, record: &log::Record<'_>) -> String {
        if self.colour {
            let open = Color::Fixed(243).paint("[");
            let close = Color::Fixed(243).paint("]");
            format!("{}{} {}{} {}", open, level(record.level()), record.target(), close, record.args())
        }
        else {
            format!("[{} {}] {}", record.level(), record.target(), record.args())
        }
    }
}

impl log::Log for Logger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true  // no need to filter after using ‘set_max_level’.
    }

    fn log(&self, record: &log::Record<'_>) {
        // Logging must never stop dog, and standard error is where a failure
        // to write would be reported, so a line that cannot be written is lost.
        drop(writeln!(io::stderr(), "{}", self.line(record)));
    }

    fn flush(&self) {
        // each line is written whole, and standard error is not buffered.
    }
}

fn level(level: log::Level) -> AnsiString<'static> {
    match level {
        log::Level::Error => Color::Red.paint("ERROR"),
        log::Level::Warn  => Color::Yellow.paint("WARN"),
        log::Level::Info  => Color::Cyan.paint("INFO"),
        log::Level::Debug => Color::Blue.paint("DEBUG"),
        log::Level::Trace => Color::Fixed(245).paint("TRACE"),
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use log::Log;

    #[test]
    fn level_labels_escape_sequences() {
        assert_eq!(level(log::Level::Error).to_string(), "\x1b[31mERROR\x1b[0m");
        assert_eq!(level(log::Level::Warn).to_string(),  "\x1b[33mWARN\x1b[0m");
        assert_eq!(level(log::Level::Info).to_string(),  "\x1b[36mINFO\x1b[0m");
        assert_eq!(level(log::Level::Debug).to_string(), "\x1b[34mDEBUG\x1b[0m");
        assert_eq!(level(log::Level::Trace).to_string(), "\x1b[38;5;245mTRACE\x1b[0m");
        assert_eq!(Color::Fixed(243).paint("[").to_string(), "\x1b[38;5;243m[\x1b[0m");
    }

    /// Configuring changes process-wide state, so every step is tested here,
    /// in order: a missing or empty value leaves logging off, a value turns
    /// it on, and a second attempt to install the logger is reported rather
    /// than fatal. Logging is switched off again at the end.
    #[test]
    fn configuring_levels() {
        configure::<&str>(None);
        configure(Some(""));
        assert_eq!(log::max_level(), log::LevelFilter::Off);

        configure(Some("1"));
        assert_eq!(log::max_level(), log::LevelFilter::Debug);

        configure(Some("trace"));
        assert_eq!(log::max_level(), log::LevelFilter::Trace);

        log::set_max_level(log::LevelFilter::Off);
    }

    fn with_record(check: impl Fn(&log::Record<'_>)) {
        let metadata = log::Metadata::builder().level(log::Level::Info).target("dog").build();
        check(&log::Record::builder().metadata(metadata).args(format_args!("a message")).build());
    }

    /// When standard error is a pipe or a file, the log has no escape codes
    /// in it; before, it always had.
    #[test]
    fn plain_and_coloured_lines() {
        with_record(|record| assert_eq!(PLAIN.line(record), "[INFO dog] a message"));
        with_record(|record| assert_eq!(COLOURED.line(record), "\x1b[38;5;243m[\x1b[0m\x1b[36mINFO\x1b[0m dog\x1b[38;5;243m]\x1b[0m a message"));
    }

    #[test]
    fn the_logger_takes_every_record() {
        with_record(|record| {
            assert!(PLAIN.enabled(record.metadata()));
            PLAIN.log(record);
            PLAIN.flush();
        });
    }
}
