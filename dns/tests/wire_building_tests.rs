use dns::{Request, Flags, Query, Labels, QClass};
use dns::record::RecordType;

use pretty_assertions::assert_eq;


#[test]
fn build_request() {
    let request = Request {
        transaction_id: 0xceac,
        flags: Flags::query(),
        query: Query {
            qname: Labels::encode("rfcs.io").unwrap(),
            qclass: QClass::Other(0x42),
            qtype: RecordType::from(0x1234),
        },
        additional: Some(Request::additional_record()),
    };

    let result = vec![
        0xce, 0xac,  // transaction ID
        0x01, 0x00,  // flags (standard query)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  // counts (1, 0, 0, 1)

        // query:
        0x04, 0x72, 0x66, 0x63, 0x73, 0x02, 0x69, 0x6f, 0x00,  // qname
        0x12, 0x34,  // type
        0x00, 0x42,  // class

        // OPT record:
        0x00,  // name
        0x00, 0x29,  // type OPT
        0x02, 0x00,  // UDP payload size
        0x00,  // higher bits
        0x00,  // EDNS(0) version
        0x00, 0x00,  // more flags
        0x00, 0x00,  // no data
    ];

    assert_eq!(request.to_bytes().unwrap(), result);
}
