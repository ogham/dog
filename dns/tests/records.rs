//! Record parsing, driven by real captured responses and targeted damage to
//! them.

use dns::{Response, WireError};
use test_support::fixtures;
use test_support::wire;

/// An NSEC record whose stated length is shorter than its next-domain name
/// used to underflow a subtraction and abort dog. It is now a malformed
/// packet like any other.
#[test]
fn nsec_shorter_than_its_next_domain_is_an_error() {
    let bytes = fixtures::response("nsec-ietf");
    let nsec = wire::first_rr(&bytes, 47);
    let name_length = u16::try_from(wire::skip_name(&bytes, nsec.rdata.start) - nsec.rdata.start).unwrap();
    assert!(name_length > 2, "the real next-domain name is longer than two bytes");

    let damaged = wire::with_rdlength(&bytes, &nsec, 2);
    assert_eq!(Response::from_bytes(&damaged).unwrap_err(),
               WireError::WrongLabelLength { stated_length: 2, length_after_labels: name_length });
}

/// The same for an RRSIG whose signer name runs past its stated length,
/// which used to underflow computing the signature length.
#[test]
fn rrsig_shorter_than_its_signer_name_is_an_error() {
    let bytes = fixtures::response("rrsig-cloudflare");
    let rrsig = wire::first_rr(&bytes, 46);
    let name_at = rrsig.rdata.start + 18;
    let name_length = u16::try_from(wire::skip_name(&bytes, name_at) - name_at).unwrap();

    let damaged = wire::with_rdlength(&bytes, &rrsig, 19);
    assert_eq!(Response::from_bytes(&damaged).unwrap_err(),
               WireError::WrongLabelLength { stated_length: 19, length_after_labels: 18 + name_length });
}
