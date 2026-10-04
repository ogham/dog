//! The names of record types and DNSSEC algorithms.
//!
//! These are data, not code: one table per IANA registry, shared by every
//! record type that needs to name a number.

/// Record type numbers and their names, from the IANA “Resource Record (RR)
/// TYPEs” registry, including the many types dog does not parse.
static RECORD_TYPES: &[(u16, &str)] = &[
    (1, "A"),           (2, "NS"),          (5, "CNAME"),       (6, "SOA"),
    (12, "PTR"),        (13, "HINFO"),      (15, "MX"),         (16, "TXT"),
    (17, "RP"),         (18, "AFSDB"),      (24, "SIG"),        (25, "KEY"),
    (28, "AAAA"),       (29, "LOC"),        (33, "SRV"),        (35, "NAPTR"),
    (36, "KX"),         (37, "CERT"),       (39, "DNAME"),      (41, "OPT"),
    (42, "APL"),        (43, "DS"),         (44, "SSHFP"),      (45, "IPSECKEY"),
    (46, "RRSIG"),      (47, "NSEC"),       (48, "DNSKEY"),     (49, "DHCID"),
    (50, "NSEC3"),      (51, "NSEC3PARAM"), (52, "TLSA"),       (53, "SMIMEA"),
    (55, "HIP"),        (59, "CDS"),        (60, "CDNSKEY"),    (61, "OPENPGPKEY"),
    (62, "CSYNC"),      (63, "ZONEMD"),     (64, "SVCB"),       (65, "HTTPS"),
    (108, "EUI48"),     (109, "EUI64"),     (249, "TKEY"),      (250, "TSIG"),
    (251, "IXFR"),      (252, "AXFR"),      (255, "ANY"),       (256, "URI"),
    (257, "CAA"),       (32768, "TA"),      (32769, "DLV"),
];

/// DNSSEC algorithm numbers and their mnemonics, from the IANA “DNS
/// Security Algorithm Numbers” registry.
static DNSSEC_ALGORITHMS: &[(u8, &str)] = &[
    (1, "RSAMD5"),              (3, "DSA"),                 (5, "RSASHA1"),
    (6, "DSA-NSEC3-SHA1"),      (7, "RSASHA1-NSEC3-SHA1"),  (8, "RSASHA256"),
    (10, "RSASHA512"),          (12, "ECC-GOST"),           (13, "ECDSAP256SHA256"),
    (14, "ECDSAP384SHA384"),    (15, "ED25519"),            (16, "ED448"),
];

/// The name of a record type, if it has one.
pub(crate) fn record_type_name(number: u16) -> Option<&'static str> {
    RECORD_TYPES.iter().find(|(n, _)| *n == number).map(|(_, name)| *name)
}

/// The number and canonical name of a record type, given its name in any case.
pub(crate) fn record_type_by_name(name: &str) -> Option<(u16, &'static str)> {
    RECORD_TYPES.iter().find(|(_, n)| n.eq_ignore_ascii_case(name)).copied()
}

/// The mnemonic of a DNSSEC algorithm, if it has one.
pub(crate) fn dnssec_algorithm_name(number: u8) -> Option<&'static str> {
    DNSSEC_ALGORITHMS.iter().find(|(n, _)| *n == number).map(|(_, name)| *name)
}

/// DS digest type numbers and their names, from the IANA “Delegation
/// Signer (DS) Resource Record (RR) Type Digest Algorithms” registry.
static DIGEST_TYPES: &[(u8, &str)] = &[
    (1, "SHA-1"),   (2, "SHA-256"),   (3, "GOST R 34.11-94"),   (4, "SHA-384"),
];

/// The name of a DS digest type, if it has one.
pub(crate) fn digest_type_name(number: u8) -> Option<&'static str> {
    DIGEST_TYPES.iter().find(|(n, _)| *n == number).map(|(_, name)| *name)
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::record::*;
    use crate::wire::Wire;

    #[test]
    fn digest_types() {
        assert_eq!((1 ..= 5).map(digest_type_name).collect::<Vec<_>>(),
                   [ Some("SHA-1"), Some("SHA-256"), Some("GOST R 34.11-94"), Some("SHA-384"), None ]);
        assert!(DIGEST_TYPES.windows(2).all(|w| w[0].0 < w[1].0));
    }

    #[test]
    fn tables_are_sorted_and_unique() {
        assert!(RECORD_TYPES.windows(2).all(|w| w[0].0 < w[1].0));
        assert!(DNSSEC_ALGORITHMS.windows(2).all(|w| w[0].0 < w[1].0));

        let mut names = RECORD_TYPES.iter().map(|(_, name)| *name).collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), RECORD_TYPES.len());
    }

    /// Every type dog parses is in the table under its own name and number.
    #[test]
    fn parsed_types_agree_with_the_table() {
        let parsed = [
            (A::NAME, A::RR_TYPE), (AAAA::NAME, AAAA::RR_TYPE), (CAA::NAME, CAA::RR_TYPE),
            (CNAME::NAME, CNAME::RR_TYPE), (DNSKEY::NAME, DNSKEY::RR_TYPE), (DS::NAME, DS::RR_TYPE),
            (EUI48::NAME, EUI48::RR_TYPE), (EUI64::NAME, EUI64::RR_TYPE), (HINFO::NAME, HINFO::RR_TYPE),
            (LOC::NAME, LOC::RR_TYPE), (MX::NAME, MX::RR_TYPE), (NAPTR::NAME, NAPTR::RR_TYPE),
            (NS::NAME, NS::RR_TYPE), (NSEC::NAME, NSEC::RR_TYPE), (OPENPGPKEY::NAME, OPENPGPKEY::RR_TYPE),
            (PTR::NAME, PTR::RR_TYPE), (RRSIG::NAME, RRSIG::RR_TYPE), (SSHFP::NAME, SSHFP::RR_TYPE),
            (SOA::NAME, SOA::RR_TYPE), (SRV::NAME, SRV::RR_TYPE), (TLSA::NAME, TLSA::RR_TYPE),
            (TXT::NAME, TXT::RR_TYPE), (URI::NAME, URI::RR_TYPE),
        ];

        for (name, number) in parsed {
            assert_eq!(record_type_name(number), Some(name));
            assert_eq!(record_type_by_name(name), Some((number, name)));
        }
        assert_eq!(record_type_name(OPT::RR_TYPE), Some("OPT"));
    }

    #[test]
    fn lookups() {
        assert_eq!(record_type_name(65), Some("HTTPS"));
        assert_eq!(record_type_name(4444), None);
        assert_eq!(record_type_by_name("svcb"), Some((64, "SVCB")));
        assert_eq!(record_type_by_name("WIBBLE"), None);
        assert_eq!(dnssec_algorithm_name(13), Some("ECDSAP256SHA256"));
        assert_eq!(dnssec_algorithm_name(2), None);
    }
}
