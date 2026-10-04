//! This build script gets run during every build. Its purpose is to put
//! together the files used for the `--help` and `--version`, which need to
//! come in both coloured and non-coloured variants. The main usage text is
//! contained in `src/usage.txt`; to make it easier to edit, backslashes (\)
//! are used instead of the beginning of ANSI escape codes.
//!
//! The version string is quite complex: release builds of a pre-release
//! version show the current Git hash and the build date, debug builds say
//! they are debug builds, and actual releases show just the version.
//!
//! The text itself is assembled by the pure functions in
//! `build-support/version.rs`; this script gathers the inputs from the
//! environment Cargo provides and writes the results into files, which are
//! included during compilation.

use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "build-support/version.rs"]
mod version;

use version::{Build, Provenance};


/// The build script entry point.
fn main() -> io::Result<()> {
    let usage = include_str!("src/usage.txt");

    let profile = cargo_env("PROFILE")?;
    let pkg_version = cargo_env("CARGO_PKG_VERSION")?;
    let missing = version::missing_features(feature_enabled("WITH_IDNA"), feature_enabled("WITH_TLS"), feature_enabled("WITH_HTTPS"));
    let build = Build { profile: &profile, version: &pkg_version, missing_features: &missing };

    let (git_hash, date) =
        if version::needs_provenance(&build) { watch_git_head()?; (git_hash(), build_date()) }
        else { (String::new(), String::new()) };
    let ver = version::version_text(&build, &Provenance { git_hash: &git_hash, date: &date });

    // We need to create these files in the Cargo output directory.
    let out = PathBuf::from(cargo_env("OUT_DIR")?);
    fs::write(out.join("version.pretty.txt"), format!("{}\n", version::convert_codes(&ver)))?;
    fs::write(out.join("version.bland.txt"), format!("{}\n", version::strip_codes(&ver)))?;

    let tagline = version::TAGLINE;
    fs::write(out.join("usage.pretty.txt"), format!("{}\n\n{}", version::convert_codes(tagline), version::convert_codes(usage)))?;
    fs::write(out.join("usage.bland.txt"), format!("{}\n\n{}", version::strip_codes(tagline), version::strip_codes(usage)))?;

    println!("cargo::rerun-if-env-changed=SOURCE_DATE_EPOCH");
    Ok(())
}

/// Reads a variable that Cargo always sets for build scripts.
fn cargo_env(name: &str) -> io::Result<String> {
    env::var(name).map_err(|e| io::Error::other(format!("Cargo did not set {name}: {e}")))
}

/// Finds whether a feature is enabled by examining the Cargo variable.
fn feature_enabled(name: &str) -> bool {
    env::var(format!("CARGO_FEATURE_{name}")).is_ok_and(|value| !value.is_empty())
}

/// Asks Cargo to run this script again whenever `HEAD` moves to another
/// commit. Without this, a commit that changed no source file left the
/// version showing the commit before it. Only files that exist are named,
/// because Cargo would run the script on every build for one that did not,
/// as in a source tree without Git, such as the one Docker builds from.
fn watch_git_head() -> io::Result<()> {
    let git = PathBuf::from(cargo_env("CARGO_MANIFEST_DIR")?).join(".git");
    let Ok(head) = fs::read_to_string(git.join("HEAD")) else { return Ok(()) };

    for file in version::git_head_files(&head) {
        let path = git.join(file);
        if path.exists() {
            println!("cargo::rerun-if-changed={}", path.display());
        }
    }

    Ok(())
}

/// The project’s current Git hash, or `unknown` when building from a
/// source tree that is not a Git checkout, or without Git installed.
fn git_hash() -> String {
    match Command::new("git").args([ "rev-parse", "--short", "HEAD" ]).output() {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        Ok(output) => {
            println!("cargo::warning=git rev-parse failed ({}); the version will say ‘unknown’", output.status);
            "unknown".into()
        }
        Err(e) => {
            println!("cargo::warning=could not run git ({e}); the version will say ‘unknown’");
            "unknown".into()
        }
    }
}

/// The build date: from `SOURCE_DATE_EPOCH` when it is set, as it is for
/// reproducible builds, and otherwise today’s date in UTC.
fn build_date() -> String {
    if let Ok(epoch) = env::var("SOURCE_DATE_EPOCH") {
        match epoch.trim().parse() {
            Ok(seconds) => return version::utc_date(seconds),
            Err(e) => println!("cargo::warning=ignoring SOURCE_DATE_EPOCH={epoch:?}: {e}"),
        }
    }

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => version::utc_date(elapsed.as_secs()),
        Err(e) => {
            println!("cargo::warning=the system clock is before 1970 ({e}); using the epoch as the build date");
            version::utc_date(0)
        }
    }
}
