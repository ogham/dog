//! Loading the fixtures captured from real servers.

use std::fs;
use std::path::{Path, PathBuf};

/// The `tests/fixtures` directory at the root of the repository.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("tests").join("fixtures")
}

/// Reads a fixture file, given its path relative to `tests/fixtures`.
///
/// # Panics
///
/// Panics if the file cannot be read: a missing fixture is a broken test.
pub fn load(relative: &str) -> Vec<u8> {
    let path = root().join(relative);
    fs::read(&path).unwrap_or_else(|e| panic!("cannot read fixture {}: {e}", path.display()))
}

/// Reads a UTF-8 fixture file, given its path relative to `tests/fixtures`.
///
/// # Panics
///
/// Panics if the file cannot be read or is not UTF-8.
pub fn text(relative: &str) -> String {
    String::from_utf8(load(relative))
        .unwrap_or_else(|e| panic!("fixture {relative} is not UTF-8: {e}"))
}

/// The raw DNS response captured for the named scenario.
pub fn response(name: &str) -> Vec<u8> {
    load(&format!("dns/{name}.response.bin"))
}

/// The raw DNS query that was sent for the named scenario.
pub fn query(name: &str) -> Vec<u8> {
    load(&format!("dns/{name}.query.bin"))
}

/// dig’s text rendering of the named scenario’s answer and authority sections.
pub fn dig(name: &str) -> String {
    text(&format!("dns/{name}.dig.txt"))
}

/// The raw HTTP/1.1 response captured for the named DNS-over-HTTPS scenario.
pub fn http_response(name: &str) -> Vec<u8> {
    load(&format!("doh/{name}.response.http"))
}

/// The raw HTTP/1.1 request that was sent for the named DNS-over-HTTPS scenario.
pub fn http_request(name: &str) -> Vec<u8> {
    load(&format!("doh/{name}.request.http"))
}

/// Every byte the server sent for the named DNS-over-HTTPS scenario over
/// HTTP/2, up to the frame that ended the response.
pub fn h2_response(name: &str) -> Vec<u8> {
    load(&format!("doh/{name}.response.h2"))
}

/// The raw HTTP/2 request that was sent for the named DNS-over-HTTPS
/// scenario, from the connection preface to the end of the body.
pub fn h2_request(name: &str) -> Vec<u8> {
    load(&format!("doh/{name}.request.h2"))
}

/// One row of `tests/fixtures/MANIFEST.tsv`, describing how a fixture was captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub tier: u8,
    pub transport: String,
    pub server: String,
    pub port: u16,
    pub qname: String,
    pub qtype: String,
    pub qclass: String,
    pub knobs: String,
    pub txid: u16,
}

impl Row {
    /// Whether the scenario went over plain DNS (UDP or TCP) rather than
    /// HTTPS, over either HTTP/1.1 (`doh`) or HTTP/2 (`doh2`).
    pub fn is_dns(&self) -> bool {
        ! self.transport.starts_with("doh")
    }

    /// The value of one `key=value` knob, such as `do` or `bufsize`.
    pub fn knob(&self, key: &str) -> Option<&str> {
        self.knobs
            .split(',')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v)
    }
}

/// Every row of the fixture manifest, in capture order.
///
/// # Panics
///
/// Panics if the manifest is missing or malformed.
pub fn manifest() -> Vec<Row> {
    let text = text("MANIFEST.tsv");
    let mut lines = text.lines();
    let header: Vec<&str> = lines.next().expect("the manifest has a header line").split('\t').collect();
    lines.filter(|line| !line.is_empty()).map(|line| parse_row(&header, line)).collect()
}

/// The manifest rows for scenarios captured over plain DNS.
pub fn dns_rows() -> Vec<Row> {
    manifest().into_iter().filter(Row::is_dns).collect()
}

fn parse_row(header: &[&str], line: &str) -> Row {
    let cells: Vec<&str> = line.split('\t').collect();
    let get = |column: &str| -> String {
        let index = header.iter().position(|h| *h == column)
            .unwrap_or_else(|| panic!("the manifest has no {column} column"));
        cells.get(index).map(|cell| (*cell).to_owned())
            .unwrap_or_else(|| panic!("manifest row {line:?} has no {column}"))
    };

    Row {
        name: get("name"),
        tier: get("tier").parse().expect("tier is a number"),
        transport: get("transport"),
        server: get("server"),
        port: get("port").parse().expect("port is a number"),
        qname: get("qname"),
        qtype: get("qtype"),
        qclass: get("qclass"),
        knobs: get("knobs"),
        txid: u16::from_str_radix(get("txid").trim_start_matches("0x"), 16).expect("txid is hex"),
    }
}
