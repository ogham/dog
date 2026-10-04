//! Writing messages to standard error.

use std::fmt;
use std::io::{self, Write};

use log::*;


/// Writes a line to standard error.
///
/// Unlike `eprintln!`, this does not panic when standard error cannot be
/// written to, such as when it is a full device: a panic aborts dog, which
/// turned the error it was trying to report into a crash. There is nowhere
/// else to report that failure, so it is only logged, and dog’s exit status
/// is what tells the caller that something went wrong.
pub fn line(args: fmt::Arguments<'_>) {
    let mut stderr = io::stderr().lock();
    if let Err(e) = stderr.write_fmt(args).and_then(|()| stderr.write_all(b"\n")) {
        debug!("Could not write to standard error: {e}");
    }
}
