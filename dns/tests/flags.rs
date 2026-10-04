//! Header flags and response codes, from real responses.

use dns::{ErrorCode, Flags, Opcode, Response};
use test_support::{fixtures, wire};

/// Encoding a request with any opcode other than QUERY used to reach an
/// `unimplemented!()`.
#[test]
fn every_opcode_encodes() {
    for opcode in 1 ..= 15 {
        let flags = Flags { opcode: Opcode::Other(opcode), .. Flags::query() };
        assert_eq!(flags.to_u16(), 0x0100 | (u16::from(opcode) << 11));
        assert_eq!(Flags::from_u16(flags.to_u16()), flags);
    }
}

/// The flags of every real response survive decoding and encoding again.
#[test]
fn real_flags_round_trip() {
    for row in fixtures::dns_rows() {
        let bytes = fixtures::response(&row.name);
        let bits = wire::flags(&bytes);
        let flags = Flags::from_u16(bits);

        // Only the 4-bit header rcode is part of the flags field; the Z bit
        // is reserved and not kept.
        assert_eq!(flags.to_u16() | (bits & 0x000F), bits & !0x0040, "{}", row.name);
    }
}

/// Google answers the STATUS opcode (2) with NOTIMP, echoing the opcode.
#[test]
fn a_real_response_to_another_opcode() {
    let response = Response::from_bytes(&fixtures::response("notimp-opcode-status")).unwrap();
    assert_eq!(response.flags.opcode, Opcode::Other(2));
    assert_eq!(response.flags.error_code, Some(ErrorCode::NotImplemented));
}

/// BIND answers an unsupported EDNS version with BADVERS, whose code (16)
/// does not fit the header’s four bits: its upper bits live in the OPT
/// record (RFC 6891 §6.1.3). They used to be ignored, so BADVERS read as
/// NOERROR.
#[test]
fn extended_rcode_from_the_opt_record() {
    let bytes = fixtures::response("badvers-bind");
    assert_eq!(wire::flags(&bytes) & 0xF, 0, "the header alone says NOERROR");

    let response = Response::from_bytes(&bytes).unwrap();
    assert_eq!(response.flags.error_code, Some(ErrorCode::BadVersion));
}

/// The private-use range is 3841 to 4095 inclusive (RFC 6895 §2.3).
#[test]
fn private_use_rcodes() {
    let bytes = fixtures::response("badvers-bind");
    let opt = wire::first_rr(&bytes, 41);
    let ttl_at = opt.rdlength_at - 4;

    for (rcode, expected) in [ (3841, ErrorCode::Private(3841)), (4095, ErrorCode::Private(4095)), (3840, ErrorCode::Other(3840)) ] {
        let mut damaged = wire::with_rcode(&bytes, rcode & 0xF);
        damaged[ttl_at] = u8::try_from(rcode >> 4).unwrap();
        let response = Response::from_bytes(&damaged).unwrap();
        assert_eq!(response.flags.error_code, Some(expected), "{rcode}");
    }
}

/// Header rcodes 6 to 15 have no name in dog, and are kept as numbers.
#[test]
fn unnamed_header_rcodes() {
    let bytes = fixtures::response("a-example");
    for rcode in 6 ..= 15 {
        let response = Response::from_bytes(&wire::with_rcode(&bytes, rcode)).unwrap();
        assert_eq!(response.flags.error_code, Some(ErrorCode::Other(rcode)));
    }
}
