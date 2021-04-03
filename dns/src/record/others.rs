use std::fmt;


/// A number representing a record type dog can’t deal with.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum UnknownQtype {

    /// An rtype number that dog is aware of, but does not know how to parse.
    HeardOf(&'static str, u16),

    /// A completely unknown rtype number.
    UnheardOf(u16),
}

impl UnknownQtype {

    /// Searches the list for an unknown type with the given name, returning a
    /// `HeardOf` variant if one is found, and `None` otherwise.
    pub fn from_type_name(type_name: &str) -> Option<Self> {
        let (name, num) = TYPES.iter().find(|t| t.0.eq_ignore_ascii_case(type_name))?;
        Some(Self::HeardOf(name, *num))
    }

    /// Returns the type number behind this unknown type.
    pub fn type_number(self) -> u16 {
        match self {
            Self::HeardOf(_, num) |
            Self::UnheardOf(num)  => num,
        }
    }
}

impl From<u16> for UnknownQtype {
    fn from(qtype: u16) -> Self {
        match TYPES.iter().find(|t| t.1 == qtype) {
            Some(tuple)  => Self::HeardOf(tuple.0, qtype),
            None         => Self::UnheardOf(qtype),
        }
    }
}

impl fmt::Display for UnknownQtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeardOf(name, _)  => write!(f, "{}", name),
            Self::UnheardOf(num)    => write!(f, "{}", num),
        }
    }
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
    ("NSEC",       47),
    ("NSEC3",      50),
    ("NSEC3PARAM", 51),
    ("OPENPGPKEY", 61),
    ("RRSIG",      46),
    ("RP",         17),
    ("SIG",        24),
    ("SMIMEA",     53),
    ("TA",      32768),
    ("TKEY",      249),
    ("TSIG",      250),
    ("URI",       256),
];


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn known() {
        assert_eq!(UnknownQtype::from(46).to_string(),
                   String::from("RRSIG"));
    }

    #[test]
    fn unknown() {
        assert_eq!(UnknownQtype::from(4444).to_string(),
                   String::from("4444"));
    }
}
