use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// An **RRSIG** _(resource record signature)_ record, which contains a
/// DNSSEC signature for an RRset. RRSIG records are used to authenticate
/// DNS data.
///
/// # References
///
/// - [RFC 4034 §3](https://tools.ietf.org/html/rfc4034#section-3) — Resource
///   Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct RRSIG {

    /// The type of the RRset that is covered by this signature.
    pub type_covered: u16,

    /// The algorithm number used to create the signature.
    pub algorithm: u8,

    /// The number of labels in the original owner name of the covered RRset.
    pub labels: u8,

    /// The TTL of the covered RRset as it appears in the authoritative zone.
    pub original_ttl: u32,

    /// The expiration time of the signature, as a Unix timestamp.
    pub signature_expiration: u32,

    /// The inception time of the signature, as a Unix timestamp.
    pub signature_inception: u32,

    /// A tag value to efficiently identify the DNSKEY used to verify this
    /// signature.
    pub key_tag: u16,

    /// The domain name of the zone that contains the signer's DNSKEY.
    pub signer_name: Labels,

    /// The cryptographic signature.
    pub signature: Vec<u8>,
}

impl Wire for RRSIG {
    const NAME: &'static str = "RRSIG";
    const RR_TYPE: u16 = 46;

    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        // Fixed fields before signer name: 2+1+1+4+4+4+2 = 18 bytes
        if stated_length < 19 {
            let mandated_length = MandatedLength::AtLeast(19);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let fixed = FixedFields::read(c)?;
        trace!("Parsed fixed fields -> {fixed:?}");

        let (signer_name, signer_name_length) = c.read_labels()?;
        trace!("Parsed signer name -> {signer_name:?}");

        // The signature is whatever the stated length leaves after the fixed
        // fields and the signer name. A name that runs past the stated
        // length makes the record malformed; subtracting blindly would
        // underflow.
        let length_after_labels = signer_name_length.saturating_add(18);
        let signature_length = stated_length.checked_sub(length_after_labels)
            .ok_or(WireError::WrongLabelLength { stated_length, length_after_labels })?;
        let mut signature = vec![0_u8; usize::from(signature_length)];
        c.read_exact(&mut signature)?;
        trace!("Parsed signature -> {signature:#x?}");

        let FixedFields { type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag } = fixed;
        Ok(Self {
            type_covered, algorithm, labels, original_ttl,
            signature_expiration, signature_inception, key_tag,
            signer_name, signature,
        })
    }
}

/// The fields of an RRSIG record that come before the signer name, which
/// all have fixed sizes.
#[derive(Debug)]
struct FixedFields {
    type_covered: u16,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
}

impl FixedFields {
    fn read(c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        // Struct fields are evaluated in the order they are written, which
        // is the order they appear on the wire.
        Ok(Self {
            type_covered:         c.read_u16::<BigEndian>()?,
            algorithm:            c.read_u8()?,
            labels:               c.read_u8()?,
            original_ttl:         c.read_u32::<BigEndian>()?,
            signature_expiration: c.read_u32::<BigEndian>()?,
            signature_inception:  c.read_u32::<BigEndian>()?,
            key_tag:              c.read_u16::<BigEndian>()?,
        })
    }
}

impl RRSIG {

    /// Returns the base64-encoded signature.
    pub fn base64_signature(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&self.signature)
    }

    /// Returns a human-readable name for the algorithm number, if known.
    pub fn algorithm_name(&self) -> Option<&'static str> {
        super::registry::dnssec_algorithm_name(self.algorithm)
    }

    /// Returns the name of the type covered, if that type has a name.
    pub fn type_covered_name(&self) -> Option<&'static str> {
        super::registry::record_type_name(self.type_covered)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x01,  // type covered (1 = A)
            0x0D,        // algorithm (13 = ECDSAP256SHA256)
            0x02,        // labels
            0x00, 0x00, 0x0E, 0x10,  // original TTL (3600)
            0x67, 0x8A, 0x1B, 0x80,  // signature expiration
            0x67, 0x68, 0x9C, 0x00,  // signature inception
            0x09, 0x43,  // key tag (2371)
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,  // "example"
            0x03, 0x63, 0x6F, 0x6D,  // "com"
            0x00,        // signer name terminator
            0xAA, 0xBB, 0xCC, 0xDD,  // signature (abbreviated)
        ];

        assert_eq!(RRSIG::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)).unwrap(),
                   RRSIG {
                       type_covered: 1,
                       algorithm: 13,
                       labels: 2,
                       original_ttl: 3600,
                       signature_expiration: 0x678A_1B80,
                       signature_inception: 0x6768_9C00,
                       key_tag: 2371,
                       signer_name: Labels::encode("example.com").unwrap(),
                       signature: vec![ 0xAA, 0xBB, 0xCC, 0xDD ],
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00, 0x01,  // type covered
            0x0D,        // algorithm
            0x02,        // labels
            0x00, 0x00, 0x0E, 0x10,  // original TTL
            0x67, 0x8A, 0x1B, 0x80,  // signature expiration
            0x67, 0x68, 0x9C, 0x00,  // signature inception
            0x09, 0x43,  // key tag
            // missing signer name and signature
        ];

        assert_eq!(RRSIG::read(u16::try_from(buf.len()).unwrap(), &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 18, mandated_length: MandatedLength::AtLeast(19) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(RRSIG::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::AtLeast(19) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00, 0x01,  // type covered
            0x0D,        // algorithm
        ];

        assert_eq!(RRSIG::read(30, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn base64_sig() {
        let rrsig = RRSIG {
            type_covered: 1,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 0,
            signature_inception: 0,
            key_tag: 2371,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![ 0xAA, 0xBB, 0xCC, 0xDD ],
        };

        assert_eq!(rrsig.base64_signature(),
                   String::from("qrvM3Q=="));
    }

    #[test]
    fn known_algorithm_name() {
        let rrsig = RRSIG {
            type_covered: 1, algorithm: 13, labels: 2, original_ttl: 0,
            signature_expiration: 0, signature_inception: 0, key_tag: 0,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![],
        };
        assert_eq!(rrsig.algorithm_name(), Some("ECDSAP256SHA256"));
    }

    #[test]
    fn known_type_covered_name() {
        let rrsig = RRSIG {
            type_covered: 48, algorithm: 13, labels: 2, original_ttl: 0,
            signature_expiration: 0, signature_inception: 0, key_tag: 0,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![],
        };
        assert_eq!(rrsig.type_covered_name(), Some("DNSKEY"));
    }

    #[test]
    fn unknown_type_covered_name() {
        let rrsig = RRSIG {
            type_covered: 9999, algorithm: 13, labels: 2, original_ttl: 0,
            signature_expiration: 0, signature_inception: 0, key_tag: 0,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![],
        };
        assert_eq!(rrsig.type_covered_name(), None);
    }
}
