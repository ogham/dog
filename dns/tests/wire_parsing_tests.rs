use std::net::Ipv4Addr;

use dns::{Response, Query, Answer, Labels, Flags, Opcode, QClass, qtype};
use dns::record::{Record, A, CNAME, OPT};


#[test]
fn parse_nothing() {
    assert!(Response::from_bytes(&[]).is_err());
}


#[test]
fn parse_response_standard() {
    let buf = &[
        0x0d, 0xcd,  // transaction ID
        0x81, 0x80,  // flags (standard query, response, no error)
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,  // counts (1, 1, 0, 1)

        // the query:
        0x03, 0x64, 0x6e, 0x73, 0x06, 0x6c, 0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x03,
        0x64, 0x6f, 0x67, 0x00,  // "dns.lookup.dog."
        0x00, 0x01,  // type A
        0x00, 0x01,  // class IN

        // the answer:
        0xc0, 0x0c,  // to find the name, backtrack to position 0x0c (12)
        0x00, 0x01,  // type A
        0x00, 0x01,  // class IN
        0x00, 0x00, 0x03, 0xa5,  // TTL (933 seconds)
        0x00, 0x04,  // record data length 4
        0x8a, 0x44, 0x75, 0x5e,  // record date (138.68.117.94)

        // the additional:
        0x00,        // no name
        0x00, 0x29,  // type OPT
        0x02, 0x00,  // UDP payload size (512)
        0x00, 0x00,  // higher bits (all 0)
        0x00,        // EDNS version
        0x00, 0x00,  // extra bits (DO bit unset)
        0x00,        // data length 0
    ];

    let response = Response {
        transaction_id: 0x0dcd,
        flags: Flags {
            response: true,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            checking_disabled: false,
            error_code: None,
        },
        queries: vec![
            Query {
                qname: Labels::encode("dns.lookup.dog").unwrap(),
                qclass: QClass::IN,
                qtype: qtype!(A),
            },
        ],
        answers: vec![
            Answer::Standard {
                qname: Labels::encode("dns.lookup.dog").unwrap(),
                qclass: QClass::IN,
                ttl: 933,
                record: Record::A(A {
                    address: Ipv4Addr::new(138, 68, 117, 94),
                }),
            }
        ],
        authorities: vec![],
        additionals: vec![
            Answer::Pseudo {
                qname: Labels::root(),
                opt: OPT {
                    udp_payload_size: 512,
                    higher_bits: 0,
                    edns0_version: 0,
                    flags: 0,
                    data: vec![],
                },
            },
        ],
    };

    assert_eq!(Response::from_bytes(buf), Ok(response));
}


#[test]
fn parse_response_with_mixed_string() {
    let buf = &[
        0x06, 0x9f,  // transaction ID
        0x81, 0x80,  // flags (standard query, response, no error)
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,  // counts (1, 1, 0, 0)

        // the query:
        0x0d, 0x63, 0x6e, 0x61, 0x6d, 0x65, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70,
        0x6c, 0x65, 0x06, 0x6c, 0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x03, 0x64, 0x6f,
        0x67, 0x00,  // "cname-example.lookup.dog"
        0x00, 0x05,  // type CNAME
        0x00, 0x01,  // class IN

        // the answer:
        0xc0, 0x0c,  // to find the name, backtrack to position 0x0c (12)
        0x00, 0x05,  // type CNAME
        0x00, 0x01,  // class IN
        0x00, 0x00, 0x03, 0x69,  // TTL (873 seconds)
        0x00, 0x06,  // record data length 6
        0x03, 0x64, 0x6e, 0x73, 0xc0, 0x1a,
        // "dns.lookup.dog.", which is "dns." + backtrack to position 0x1a (28)
    ];

    let response = Response {
        transaction_id: 0x069f,
        flags: Flags {
            response: true,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            checking_disabled: false,
            error_code: None,
        },
        queries: vec![
            Query {
                qname: Labels::encode("cname-example.lookup.dog").unwrap(),
                qclass: QClass::IN,
                qtype: qtype!(CNAME),
            },
        ],
        answers: vec![
            Answer::Standard {
                qname: Labels::encode("cname-example.lookup.dog").unwrap(),
                qclass: QClass::IN,
                ttl: 873,
                record: Record::CNAME(CNAME {
                    domain: Labels::encode("dns.lookup.dog").unwrap(),
                }),
            }
        ],
        authorities: vec![],
        additionals: vec![],
    };

    assert_eq!(Response::from_bytes(buf), Ok(response));
}
