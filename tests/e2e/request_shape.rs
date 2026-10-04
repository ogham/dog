//! What dog actually puts on the wire, as seen by the server.

use test_support::fixtures;
use test_support::mock::{self, Server, Udp};
use test_support::wire;

use crate::common::{dog, dog_can_send, question_args, Run};

/// A server that answers whatever it is asked with the real answer for
/// `a-example.lookup.dog`, repeating the question it was sent, so that dog
/// accepts it as the answer.
fn replay_server() -> Server {
    mock::udp(Udp::Echo(fixtures::response("a-example")))
}

/// Runs dog against a fresh server and returns the queries it received.
fn queries_for(args: &[&str]) -> Vec<Vec<u8>> {
    let server = replay_server();
    let run = Run::of(dog().args([ "-U" ]).args(args).arg(server.at()));
    assert_eq!(run.status, 0, "{run:?}");
    server.requests()
}

fn only_query(args: &[&str]) -> Vec<u8> {
    let mut queries = queries_for(args);
    assert_eq!(queries.len(), 1);
    queries.remove(0)
}

fn opt(query: &[u8]) -> Option<&[u8]> {
    let span = wire::rr_spans(query).into_iter().find(|span| span.rtype == 41)?;
    Some(&query[span.name_at ..])
}

/// dog’s queries are byte-for-byte what the capture script sent to real
/// servers, for every fixture whose query dog can express. The script
/// builds its queries independently, following the wire format by hand.
#[test]
fn queries_match_the_captured_queries() {
    let rows = fixtures::dns_rows().into_iter().filter(dog_can_send).collect::<Vec<_>>();
    assert!(rows.len() > 50, "only {} fixtures", rows.len());

    for row in rows {
        let server = replay_server();
        let txid = format!("{:#06x}", row.txid);
        let run = Run::of(dog().args([ "-U", "--txid", txid.as_str() ]).args(question_args(&row)).arg(server.at()));
        assert_eq!(run.status, 0, "{}: {run:?}", row.name);
        assert_eq!(server.requests(), vec![ fixtures::query(&row.name) ], "{}", row.name);
    }
}

#[test]
fn default_query_asks_for_recursion_with_edns() {
    let query = only_query(&[ "a-example.lookup.dog" ]);
    assert_eq!(wire::flags(&query), 0x0100);
    assert_eq!(wire::counts(&query), [ 1, 0, 0, 1 ]);
    // An OPT record with a 512-byte payload size, version 0, no flags, no data.
    assert_eq!(opt(&query), Some(&[ 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 0 ][..]));
}

#[test]
fn header_tweaks_set_their_flags() {
    assert_eq!(wire::flags(&only_query(&[ "-Z", "aa", "x.example" ])), 0x0500);
    assert_eq!(wire::flags(&only_query(&[ "-Z", "authoritative", "x.example" ])), 0x0500);
    assert_eq!(wire::flags(&only_query(&[ "-Z", "ad", "x.example" ])), 0x0120);
    assert_eq!(wire::flags(&only_query(&[ "-Z", "authentic", "x.example" ])), 0x0120);
    assert_eq!(wire::flags(&only_query(&[ "-Z", "cd", "x.example" ])), 0x0110);
    assert_eq!(wire::flags(&only_query(&[ "-Z", "checking-disabled", "x.example" ])), 0x0110);
    assert_eq!(wire::flags(&only_query(&[ "-Z", "aa", "-Z", "ad", "-Z", "cd", "x.example" ])), 0x0530);
}

#[test]
fn edns_tweaks_change_the_opt_record() {
    assert_eq!(opt(&only_query(&[ "-Z", "do", "x.example" ])), Some(&[ 0, 0, 41, 2, 0, 0, 0, 0x80, 0, 0, 0 ][..]));
    assert_eq!(opt(&only_query(&[ "-Z", "dnssec-ok", "x.example" ])), Some(&[ 0, 0, 41, 2, 0, 0, 0, 0x80, 0, 0, 0 ][..]));
    assert_eq!(opt(&only_query(&[ "-Z", "bufsize=1232", "x.example" ])), Some(&[ 0, 0, 41, 4, 0xd0, 0, 0, 0, 0, 0, 0 ][..]));
    // The help showed `-Z=TWEAKS`, and that form was refused.
    assert_eq!(opt(&only_query(&[ "-Z=do", "x.example" ])), Some(&[ 0, 0, 41, 2, 0, 0, 0, 0x80, 0, 0, 0 ][..]));
    assert_eq!(opt(&only_query(&[ "--edns", "disable", "x.example" ])), None);
    assert_eq!(opt(&only_query(&[ "--edns", "off", "x.example" ])), None);
    assert!(opt(&only_query(&[ "--edns", "show", "x.example" ])).is_some());
    assert!(opt(&only_query(&[ "--edns", "hide", "x.example" ])).is_some());
}

#[test]
fn transaction_ids() {
    assert_eq!(wire::txid(&only_query(&[ "--txid", "0x1234", "x.example" ])), 0x1234);
    assert_eq!(wire::txid(&only_query(&[ "--txid", "4660", "x.example" ])), 0x1234);

    // Without --txid, IDs are random: two runs sharing one is a 1-in-65536
    // chance, so twenty runs all sharing one means they are not random.
    let ids = (0 .. 20).map(|_| wire::txid(&only_query(&[ "x.example" ]))).collect::<std::collections::BTreeSet<_>>();
    assert!(ids.len() > 1, "{ids:?}");
}

#[test]
fn classes_and_types() {
    let end = |query: &[u8]| wire::question_end(query);
    let tail = |query: &[u8]| (wire::get_u16(query, end(query) - 4), wire::get_u16(query, end(query) - 2));

    assert_eq!(tail(&only_query(&[ "x.example" ])), (1, 1));
    assert_eq!(tail(&only_query(&[ "MX", "x.example" ])), (15, 1));
    assert_eq!(tail(&only_query(&[ "mx", "x.example" ])), (15, 1));
    assert_eq!(tail(&only_query(&[ "-t", "65", "x.example" ])), (65, 1));
    assert_eq!(tail(&only_query(&[ "CH", "TXT", "x.example" ])), (16, 3));
    assert_eq!(tail(&only_query(&[ "--class", "HS", "x.example" ])), (1, 4));
    assert_eq!(tail(&only_query(&[ "--class", "254", "x.example" ])), (1, 254));

    // A class by number is the class with that name, so the answer, with
    // the question repeated, is accepted; before, dog timed out waiting.
    assert_eq!(tail(&only_query(&[ "--class", "3", "x.example" ])), (1, 3));

    // The generic forms of RFC 3597, which used to be taken as a domain
    // when given plainly, and refused by `-t`.
    assert_eq!(tail(&only_query(&[ "TYPE65", "x.example" ])), (65, 1));
    assert_eq!(tail(&only_query(&[ "-t", "TYPE28", "x.example" ])), (28, 1));
    assert_eq!(tail(&only_query(&[ "CLASS3", "TXT", "x.example" ])), (16, 3));
}

#[test]
fn every_combination_of_domains_and_types_is_asked() {
    let queries = queries_for(&[ "-q", "one.example", "-q", "two.example", "-t", "A", "-t", "AAAA" ]);
    let questions = queries.iter()
        .map(|query| query[wire::HEADER_LEN .. wire::question_end(query)].to_vec())
        .collect::<Vec<_>>();
    assert_eq!(questions, vec![
        [ &b"\x03one\x07example\x00"[..], &[ 0, 1, 0, 1 ] ].concat(),
        [ &b"\x03one\x07example\x00"[..], &[ 0, 28, 0, 1 ] ].concat(),
        [ &b"\x03two\x07example\x00"[..], &[ 0, 1, 0, 1 ] ].concat(),
        [ &b"\x03two\x07example\x00"[..], &[ 0, 28, 0, 1 ] ].concat(),
    ]);
}

#[test]
fn nameserver_flag_selects_the_server() {
    let server = replay_server();
    let address = server.addr().to_string();
    let run = Run::of(dog().args([ "-U", "-n", address.as_str(), "x.example" ]));
    assert_eq!(run.status, 0, "{run:?}");
    assert_eq!(server.requests().len(), 1);
}

#[cfg(feature = "with_idna")]
#[test]
fn unicode_names_are_sent_as_punycode() {
    let query = only_query(&[ "bücher.example" ]);
    assert_eq!(&query[wire::HEADER_LEN .. wire::question_end(&query) - 4], b"\x0dxn--bcher-kva\x07example\x00");
}

#[cfg(not(feature = "with_idna"))]
#[test]
fn unicode_names_are_sent_as_utf8_without_idna() {
    let query = only_query(&[ "bücher.example" ]);
    assert_eq!(&query[wire::HEADER_LEN .. wire::question_end(&query) - 4], "\x07bücher\x07example\x00".as_bytes());
}
