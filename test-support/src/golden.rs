//! Golden-file assertions for command output.
//!
//! A golden file is the exact output dog produced for a case, checked in
//! under `tests/golden/`. Running the tests with `DOG_BLESS=1` (or `just
//! bless`) rewrites the files from the current output instead of comparing;
//! the resulting diff is then reviewed like any other change.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// The `tests/golden` directory at the root of the repository.
pub fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("golden")
}

/// Whether the tests are rewriting golden files rather than comparing them.
pub fn blessing() -> bool {
    env::var_os("DOG_BLESS").is_some_and(|value| value == "1")
}

/// Compares `actual` with the golden file `tests/golden/<case>.<stream>`, or
/// writes it there when blessing.
///
/// # Panics
///
/// Panics if the output differs, or the golden file is missing.
pub fn assert_golden(case: &str, stream: &str, actual: &str) {
    let path = dir().join(format!("{case}.{stream}"));
    if blessing() {
        write(&path, actual);
        return;
    }

    let expected = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("cannot read golden file {} ({e}); run `just bless` to create it", path.display())
    });
    pretty_assertions::assert_eq!(expected, actual, "output differs from {}", path.display());
}

fn write(path: &Path, contents: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| panic!("cannot create {}: {e}", parent.display()));
    }
    fs::write(path, contents).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

/// Replaces the parts of dog’s output that change from run to run: the
/// number in “Ran in 12ms” and the values in a JSON `duration` object.
pub fn normalise_timing(output: &str) -> String {
    [ "Ran in ", "\"secs\":", "\"millis\":" ].iter()
        .fold(output.to_owned(), |text, marker| replace_numbers_after(&text, marker))
}

/// Replaces the run of digits and dots after each `marker` with `N`.
pub fn replace_numbers_after(text: &str, marker: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(found) = rest.find(marker) {
        let after = found + marker.len();
        out.push_str(&rest[.. after]);
        rest = &rest[after ..];

        let digits = rest.find(|c: char| !(c.is_ascii_digit() || c == '.')).unwrap_or(rest.len());
        if digits > 0 {
            out.push('N');
        }
        rest = &rest[digits ..];
    }
    out.push_str(rest);
    out
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normalises_text_and_json_timing() {
        assert_eq!(normalise_timing("A x.\nRan in 12ms\n"), "A x.\nRan in Nms\n");
        assert_eq!(normalise_timing("Ran in 0.013s"), "Ran in Ns");
        assert_eq!(normalise_timing(r#"{"duration":{"secs":0,"millis":7}}"#), r#"{"duration":{"secs":N,"millis":N}}"#);
        assert_eq!(normalise_timing("no timing here"), "no timing here");
        assert_eq!(replace_numbers_after("Ran in x", "Ran in "), "Ran in x");
    }

    #[test]
    fn golden_dir_is_at_the_repository_root() {
        assert!(dir().ends_with("tests/golden"));
    }
}
