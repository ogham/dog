//! Assembling the text of dog’s `--version` and `--help` output.
//!
//! `build.rs` includes this file to write that text out at compile time,
//! and `tests/build_support.rs` includes it to test it. Everything here is
//! a pure function of its arguments; the build script does the I/O.

/// The first line of both the help and version text.
pub const TAGLINE: &str = "dog \\1;32m●\\0m command-line DNS client";

/// The project’s web site.
pub const URL: &str = "https://dns.lookup.dog/";

/// What the build script knows about the build it is running in.
#[derive(Debug, Clone, Copy)]
pub struct Build<'a> {

    /// Cargo’s build profile, `debug` or `release`.
    pub profile: &'a str,

    /// The package version, from `Cargo.toml`.
    pub version: &'a str,

    /// The default features that were compiled out, such as `-idna, -tls`.
    pub missing_features: &'a str,
}

/// Where a build comes from, for pre-release version strings.
#[derive(Debug, Clone, Copy)]
pub struct Provenance<'a> {

    /// The short Git commit hash.
    pub git_hash: &'a str,

    /// The build date, as `YYYY-MM-DD`.
    pub date: &'a str,
}

/// The usage and version text marks colours with a backslash in place of
/// the escape character, so it stays readable; this turns those into real
/// ANSI escape codes.
pub fn convert_codes(input: &str) -> String {
    input.replace('\\', "\x1B[")
}

/// Removes the colour codes, for output that is not going to a terminal.
pub fn strip_codes(input: &str) -> String {
    input.replace("\\0m", "")
         .replace("\\1m", "")
         .replace("\\4m", "")
         .replace("\\32m", "")
         .replace("\\33m", "")
         .replace("\\1;31m", "")
         .replace("\\1;32m", "")
         .replace("\\1;33m", "")
         .replace("\\1;4;34m", "")
}

/// The comma-separated list of default features that were compiled out.
pub fn missing_features(idna: bool, tls: bool, https: bool) -> String {
    let features = [ (idna, "-idna"), (tls, "-tls"), (https, "-https") ];
    features.iter()
        .filter(|(enabled, _)| !enabled)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether the build needs to know where it came from: only release builds
/// of a pre-release version show a commit hash and date.
pub fn needs_provenance(build: &Build<'_>) -> bool {
    build.profile != "debug" && build.version.ends_with("-pre")
}

/// The files in the `.git` directory whose change means `HEAD` is now at a
/// different commit, given what `HEAD` contains: `HEAD` itself, and when it
/// names a branch, that branch’s ref, and the packed refs, where Git keeps
/// the ref instead once it has packed them.
pub fn git_head_files(head: &str) -> Vec<String> {
    let mut files = vec![ "HEAD".to_owned() ];
    if let Some(reference) = head.trim().strip_prefix("ref: ") {
        files.push(reference.to_owned());
        files.push("packed-refs".to_owned());
    }
    files
}

/// The version text, with colour codes still marked by backslashes.
/// `provenance` is only used when [`needs_provenance`] says so.
pub fn version_text(build: &Build<'_>, provenance: &Provenance<'_>) -> String {
    let mut number = build.version.to_owned();
    if !build.missing_features.is_empty() {
        number.push_str(&format!(" [{}]", build.missing_features));
    }

    if build.profile == "debug" {
        format!("{TAGLINE}\nv{number} \\1;31m(pre-release debug build!)\\0m\n\\1;4;34m{URL}\\0m")
    }
    else if needs_provenance(build) {
        format!("{TAGLINE}\nv{number} [{}] built on {} \\1;31m(pre-release!)\\0m\n\\1;4;34m{URL}\\0m",
                provenance.git_hash, provenance.date)
    }
    else {
        format!("{TAGLINE}\nv{number}\n\\1;4;34m{URL}\\0m")
    }
}

/// The calendar date, `YYYY-MM-DD` in UTC, of a number of seconds since the
/// Unix epoch.
///
/// This is Howard Hinnant’s `civil_from_days` algorithm, restricted to dates
/// on or after 1970, so every intermediate value is non-negative.
pub fn utc_date(epoch_seconds: u64) -> String {
    let days = epoch_seconds / 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 { shifted_month + 3 } else { shifted_month - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}
