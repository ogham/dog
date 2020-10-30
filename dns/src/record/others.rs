use std::fmt;


/// A number representing a record type dog can’t deal with.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum UnknownQtype {

    /// An rtype number that dog is aware of, but does not know how to parse.
    HeardOf(&'static str),

    /// A completely unknown rtype number.
    UnheardOf(u16),
}

impl From<u16> for UnknownQtype {
    fn from(qtype: u16) -> Self {
        match TYPES.iter().find(|t| t.1 == qtype) {
            Some(tuple)  => Self::HeardOf(tuple.0),
            None         => Self::UnheardOf(qtype),
        }
    }
}

impl fmt::Display for UnknownQtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeardOf(name)   => write!(f, "{}", name),
            Self::UnheardOf(num)  => write!(f, "{}", num),
        }
    }
}

/// Looks up a record type for a name dog knows about, but still doesn’t know
/// how to parse.
pub fn find_other_qtype_number(name: &str) -> Option<u16> {
    TYPES.iter().find(|t| t.0 == name).map(|t| t.1)
}

/// Mapping of record type names to their assigned numbers.
static TYPES: &[(&str, u16)] = &[
    ("AFSDB",      18),
    ("ANY",       255),
    ("APL",        42),
    ("AXFR",      252),
    ("CDNSKEY",    60),
    ("CDS",        59),
    ("CERT",       37),
    ("CSYNC",      62),
    ("DHCID",      49),
    ("DLV",     32769),
    ("DNAME",      39),
    ("DNSKEEYE",   48),
    ("DS",         43),
    ("HIP",        55),
    ("IPSECKEY",   45),
    ("IXFR",      251),
    ("KEY",        25),
    ("KX",         36),
    ("LOC",        29),
    ("NAPTR",      35),
    ("NSEC",       47),
    ("NSEC3",      50),
    ("NSEC3PARAM", 51),
    ("OPENPGPKEY", 61),
    ("RRSIG",      46),
    ("RP",         17),
    ("SIG",        24),
    ("SMIMEA",     53),
    ("SSHFP",      44),
    ("TA",      32768),
    ("TKEY",      249),
    ("TLSA",       52),
    ("TSIG",      250),
    ("URI",       256),
];
