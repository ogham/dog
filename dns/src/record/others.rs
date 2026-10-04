use std::fmt;

use super::registry;


/// A number representing a record type dog can’t deal with.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum UnknownQtype {

    /// An rtype number that dog is aware of, but does not know how to parse.
    HeardOf(&'static str, u16),

    /// A completely unknown rtype number.
    UnheardOf(u16),
}

impl UnknownQtype {

    /// Searches the registry for a type with the given name, returning a
    /// `HeardOf` variant if one is found, and `None` otherwise.
    pub fn from_type_name(type_name: &str) -> Option<Self> {
        let (number, name) = registry::record_type_by_name(type_name)?;
        Some(Self::HeardOf(name, number))
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
        match registry::record_type_name(qtype) {
            Some(name)  => Self::HeardOf(name, qtype),
            None        => Self::UnheardOf(qtype),
        }
    }
}

impl fmt::Display for UnknownQtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeardOf(name, _)  => write!(f, "{name}"),
            Self::UnheardOf(num)    => write!(f, "{num}"),
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn known() {
        assert_eq!(UnknownQtype::from(50).to_string(),
                   String::from("NSEC3"));
    }

    #[test]
    fn unknown() {
        assert_eq!(UnknownQtype::from(4444).to_string(),
                   String::from("4444"));
    }

    #[test]
    fn by_name() {
        assert_eq!(UnknownQtype::from_type_name("svcb"), Some(UnknownQtype::HeardOf("SVCB", 64)));
        assert_eq!(UnknownQtype::from_type_name("wibble"), None);
    }

    #[test]
    fn numbers() {
        assert_eq!(UnknownQtype::HeardOf("HTTPS", 65).type_number(), 65);
        assert_eq!(UnknownQtype::UnheardOf(4444).type_number(), 4444);
    }
}
