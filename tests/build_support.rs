//! The version and help text assembled by the build script.

#[path = "../build-support/version.rs"]
mod version;

use version::{Build, Provenance};

const PROVENANCE: Provenance<'static> = Provenance { git_hash: "abc1234", date: "2026-09-11" };

#[test]
fn debug_builds_say_so() {
    let build = Build { profile: "debug", version: "0.2.0-pre", missing_features: "" };
    assert!(!version::needs_provenance(&build));
    assert_eq!(version::version_text(&build, &PROVENANCE),
               "dog \\1;32m●\\0m command-line DNS client\nv0.2.0-pre \\1;31m(pre-release debug build!)\\0m\n\\1;4;34mhttps://dns.lookup.dog/\\0m");
}

#[test]
fn release_builds_of_pre_releases_show_where_they_came_from() {
    let build = Build { profile: "release", version: "0.2.0-pre", missing_features: "" };
    assert!(version::needs_provenance(&build));
    assert_eq!(version::version_text(&build, &PROVENANCE),
               "dog \\1;32m●\\0m command-line DNS client\nv0.2.0-pre [abc1234] built on 2026-09-11 \\1;31m(pre-release!)\\0m\n\\1;4;34mhttps://dns.lookup.dog/\\0m");
}

#[test]
fn actual_releases_show_just_the_version() {
    let build = Build { profile: "release", version: "0.2.0", missing_features: "" };
    assert!(!version::needs_provenance(&build));
    assert_eq!(version::version_text(&build, &PROVENANCE),
               "dog \\1;32m●\\0m command-line DNS client\nv0.2.0\n\\1;4;34mhttps://dns.lookup.dog/\\0m");
}

#[test]
fn missing_features_are_listed() {
    assert_eq!(version::missing_features(true, true, true), "");
    assert_eq!(version::missing_features(false, true, true), "-idna");
    assert_eq!(version::missing_features(true, false, false), "-tls, -https");
    assert_eq!(version::missing_features(false, false, false), "-idna, -tls, -https");

    let build = Build { profile: "release", version: "0.2.0", missing_features: "-idna, -tls, -https" };
    assert!(version::version_text(&build, &PROVENANCE).contains("v0.2.0 [-idna, -tls, -https]\n"));
}

#[test]
fn colour_codes() {
    assert_eq!(version::convert_codes("\\1;32m●\\0m"), "\x1b[1;32m●\x1b[0m");
    assert_eq!(version::strip_codes("\\1;32m●\\0m plain \\33mwarn\\0m"), "● plain warn");
}

/// The plain version text used to keep a stray `m` in front of the URL,
/// because stripping the colours removed `\1;4;34` but not the `m` that
/// ends it.
#[test]
fn stripping_the_url_colour_leaves_just_the_url() {
    assert_eq!(version::strip_codes("\\1;4;34mhttps://dns.lookup.dog/\\0m"), "https://dns.lookup.dog/");
}

#[test]
fn utc_dates() {
    assert_eq!(version::utc_date(0), "1970-01-01");
    assert_eq!(version::utc_date(86_399), "1970-01-01");
    assert_eq!(version::utc_date(86_400), "1970-01-02");
    assert_eq!(version::utc_date(951_782_400), "2000-02-29");
    assert_eq!(version::utc_date(951_868_800), "2000-03-01");
    assert_eq!(version::utc_date(1_700_000_000), "2023-11-14");
    assert_eq!(version::utc_date(1_767_225_599), "2025-12-31");
    assert_eq!(version::utc_date(1_767_225_600), "2026-01-01");
    assert_eq!(version::utc_date(4_102_444_800), "2100-01-01");
}

/// A commit that changed no source file used to leave the version showing
/// the commit before it, because nothing told Cargo that `HEAD` had moved.
#[test]
fn the_files_that_say_which_commit_is_checked_out() {
    assert_eq!(version::git_head_files("ref: refs/heads/modernization\n"), [ "HEAD", "refs/heads/modernization", "packed-refs" ]);
    assert_eq!(version::git_head_files("4aaf36c48ade9386c67aaa206e90d42f359d934a\n"), [ "HEAD" ]);
}
