//! This build script gets run during every build. Its purpose is to put
//! together the files used for the `--help` and `--version`, which need to
//! come in both coloured and non-coloured variants. The main usage text is
//! contained in `src/usage.txt`; to make it easier to edit, backslashes (\)
//! are used instead of the beginning of ANSI escape codes.
//!
//! The version string is quite complex: we want to show the version,
//! current Git hash, and compilation date when building *debug*
//! versions, but just the version for *release* versions.
//!
//! This script generates the string from the environment variables
//! that Cargo adds (http://doc.crates.io/environment-variables.html)
//! and runs `git` to get the SHA1 hash. It then writes the strings
//! into files, which we can include during compilation.

use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use datetime::{LocalDateTime, ISO};
use regex::Regex;


/// The build script entry point.
fn main() -> io::Result<()> {
    let usage   = include_str!("src/usage.txt");
    let tagline = "dog \\1;32m●\\0m command-line DNS client";
    let url     = "https://dns.lookup.dog/";

    let ver = if is_development_version() {
            format!("{}\nv{} [{}] built on {} \\1;31m(pre-release!)\\0m\n\\1;4;34m{}\\0m", tagline, cargo_version(), git_hash(), build_date(), url)
        }
        else {
            format!("{}\nv{}\n\\1;4;34m{}\\0m", tagline, cargo_version(), url)
        };

    // We need to create these files in the Cargo output directory.
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // The bits .txt files contain ANSI escape codes, ish.
    let control_code = Regex::new(r##"\\.+?m"##).unwrap();

    // Pretty version text
    let mut f = File::create(&out.join("version.pretty.txt"))?;
    write!(f, "{}\n", ver.replace("\\", "\x1B["))?;

    // Bland version text
    let mut f = File::create(&out.join("version.bland.txt"))?;
    write!(f, "{}\n", control_code.replace_all(&ver, ""))?;

    // Pretty usage text
    let mut f = File::create(&out.join("usage.pretty.txt"))?;
    write!(f, "{}\n\n{}", tagline.replace("\\", "\x1B["), usage.replace("\\", "\x1B["))?;

    // Bland usage text
    let mut f = File::create(&out.join("usage.bland.txt"))?;
    write!(f, "{}\n\n{}", control_code.replace_all(tagline, ""), control_code.replace_all(usage, ""))?;

    Ok(())
}


/// Retrieve the project’s current Git hash, as a string.
fn git_hash() -> String {
    use std::process::Command;

    String::from_utf8_lossy(
        &Command::new("git")
            .args(&["rev-parse", "--short", "HEAD"])
            .output().unwrap()
            .stdout).trim().to_string()
}


/// Whether we should show pre-release info in the version string.
///
/// Both weekly releases and actual releases are --release releases,
/// but actual releases will have a proper version number.
fn is_development_version() -> bool {
    cargo_version().ends_with("-pre") || env::var("PROFILE").unwrap() == "debug"
}


/// Retrieves the [package] version in Cargo.toml as a string.
fn cargo_version() -> String {
    env::var("CARGO_PKG_VERSION").unwrap()
}


/// Formats the current date as an ISO 8601 string.
fn build_date() -> String {
    let now = LocalDateTime::now();
    format!("{}", now.date().iso())
}
