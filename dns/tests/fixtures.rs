//! Parsing every response captured from a real server, and every way of
//! damaging one.

use dns::Response;
use test_support::fixtures;
use test_support::wire;

#[test]
fn every_captured_response_parses() {
    let rows = fixtures::dns_rows();
    assert!(rows.len() > 60, "expected every captured fixture, found {}", rows.len());

    for row in rows {
        let bytes = fixtures::response(&row.name);
        let response = Response::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{} does not parse: {e:?}", row.name));

        let [ questions, answers, authorities, additionals ] = wire::counts(&bytes).map(usize::from);
        assert_eq!(response.transaction_id, row.txid, "{}", row.name);
        assert!(response.flags.response, "{}", row.name);
        assert_eq!(response.queries.len(), questions, "{}", row.name);
        assert_eq!(response.answers.len(), answers, "{}", row.name);
        assert_eq!(response.authorities.len(), authorities, "{}", row.name);
        assert_eq!(response.additionals.len(), additionals, "{}", row.name);
    }
}

/// A response cut short anywhere is an error, never a partial success.
#[test]
fn every_truncation_is_an_error() {
    for row in fixtures::dns_rows() {
        let bytes = fixtures::response(&row.name);
        for len in 0 .. bytes.len() {
            assert!(Response::from_bytes(&bytes[.. len]).is_err(), "{} parsed when cut to {len} bytes", row.name);
        }
    }
}

/// Damaging any single byte of any real response never makes the parser
/// panic. Whether a damaged response parses is not the point; that it
/// returns at all is.
#[test]
fn single_byte_damage_never_panics() {
    for row in fixtures::dns_rows() {
        let bytes = fixtures::response(&row.name);
        for at in 0 .. bytes.len() {
            for value in [ 0x00, 0xFF, bytes[at] ^ 0x80, bytes[at].wrapping_add(1) ] {
                let mut damaged = bytes.clone();
                damaged[at] = value;
                let _outcome = Response::from_bytes(&damaged);
            }
        }
    }
}
