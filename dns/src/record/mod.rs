//! All the DNS record types, as well as how to parse each type.

use crate::wire::*;


mod a;
pub use self::a::A;

mod aaaa;
pub use self::aaaa::AAAA;

mod caa;
pub use self::caa::CAA;

mod cname;
pub use self::cname::CNAME;

mod eui48;
pub use self::eui48::EUI48;

mod eui64;
pub use self::eui64::EUI64;

mod hinfo;
pub use self::hinfo::HINFO;

mod loc;
pub use self::loc::LOC;

mod mx;
pub use self::mx::MX;

mod naptr;
pub use self::naptr::NAPTR;

mod ns;
pub use self::ns::NS;

mod openpgpkey;
pub use self::openpgpkey::OPENPGPKEY;

mod opt;
pub use self::opt::OPT;

mod ptr;
pub use self::ptr::PTR;

mod sshfp;
pub use self::sshfp::SSHFP;

mod soa;
pub use self::soa::SOA;

mod srv;
pub use self::srv::SRV;

mod tlsa;
pub use self::tlsa::TLSA;

mod txt;
pub use self::txt::TXT;

mod uri;
pub use self::uri::URI;


mod others;
pub use self::others::UnknownQtype;


/// A record that’s been parsed from a byte buffer.
#[derive(PartialEq, Debug)]
#[allow(missing_docs)]
pub enum Record {
    A(A),
    AAAA(AAAA),
    CAA(CAA),
    CNAME(CNAME),
    EUI48(EUI48),
    EUI64(EUI64),
    HINFO(HINFO),
    LOC(LOC),
    MX(MX),
    NAPTR(NAPTR),
    NS(NS),
    OPENPGPKEY(OPENPGPKEY),
    // OPT is not included here.
    PTR(PTR),
    SSHFP(SSHFP),
    SOA(SOA),
    SRV(SRV),
    TLSA(TLSA),
    TXT(TXT),
    URI(URI),

    /// A record with a type that we don’t recognise.
    Other {

        /// The number that’s meant to represent the record type.
        type_number: UnknownQtype,

        /// The undecodable bytes that were in this record.
        bytes: Vec<u8>,
    },
}


/// The type of a record that may or may not be one of the known ones. Has no
/// data associated with it other than what type of record it is.
#[derive(PartialEq, Debug, Copy, Clone)]
#[allow(missing_docs)]
pub enum RecordType {
    A,
    AAAA,
    CAA,
    CNAME,
    EUI48,
    EUI64,
    HINFO,
    LOC,
    MX,
    NAPTR,
    NS,
    OPENPGPKEY,
    PTR,
    SSHFP,
    SOA,
    SRV,
    TLSA,
    TXT,
    URI,

    /// A record type we don’t recognise.
    Other(UnknownQtype),
}

impl From<u16> for RecordType {
    fn from(type_number: u16) -> Self {
        macro_rules! try_record {
            ($record:tt) => {
                if $record::RR_TYPE == type_number {
                    return RecordType::$record;
                }
            }
        }

        try_record!(A);
        try_record!(AAAA);
        try_record!(CAA);
        try_record!(CNAME);
        try_record!(EUI48);
        try_record!(EUI64);
        try_record!(HINFO);
        try_record!(LOC);
        try_record!(MX);
        try_record!(NAPTR);
        try_record!(NS);
        try_record!(OPENPGPKEY);
        // OPT is handled separately
        try_record!(PTR);
        try_record!(SSHFP);
        try_record!(SOA);
        try_record!(SRV);
        try_record!(TLSA);
        try_record!(TXT);
        try_record!(URI);

        RecordType::Other(UnknownQtype::from(type_number))
    }
}


impl RecordType {

    /// Determines the record type with a given name, or `None` if none is
    /// known. Matches names case-insensitively.
    pub fn from_type_name(type_name: &str) -> Option<Self> {
        macro_rules! try_record {
            ($record:tt) => {
                if $record::NAME.eq_ignore_ascii_case(type_name) {
                    return Some(Self::$record);
                }
            }
        }

        try_record!(A);
        try_record!(AAAA);
        try_record!(CAA);
        try_record!(CNAME);
        try_record!(EUI48);
        try_record!(EUI64);
        try_record!(HINFO);
        try_record!(LOC);
        try_record!(MX);
        try_record!(NAPTR);
        try_record!(NS);
        try_record!(OPENPGPKEY);
        // OPT is elsewhere
        try_record!(PTR);
        try_record!(SSHFP);
        try_record!(SOA);
        try_record!(SRV);
        try_record!(TLSA);
        try_record!(TXT);
        try_record!(URI);

        UnknownQtype::from_type_name(type_name).map(Self::Other)
    }

    /// Returns the record type number associated with this record type.
    pub fn type_number(self) -> u16 {
        match self {
            Self::A           => A::RR_TYPE,
            Self::AAAA        => AAAA::RR_TYPE,
            Self::CAA         => CAA::RR_TYPE,
            Self::CNAME       => CNAME::RR_TYPE,
            Self::EUI48       => EUI48::RR_TYPE,
            Self::EUI64       => EUI64::RR_TYPE,
            Self::HINFO       => HINFO::RR_TYPE,
            Self::LOC         => LOC::RR_TYPE,
            Self::MX          => MX::RR_TYPE,
            Self::NAPTR       => NAPTR::RR_TYPE,
            Self::NS          => NS::RR_TYPE,
            Self::OPENPGPKEY  => OPENPGPKEY::RR_TYPE,
            // Wherefore art thou, OPT
            Self::PTR         => PTR::RR_TYPE,
            Self::SSHFP       => SSHFP::RR_TYPE,
            Self::SOA         => SOA::RR_TYPE,
            Self::SRV         => SRV::RR_TYPE,
            Self::TLSA        => TLSA::RR_TYPE,
            Self::TXT         => TXT::RR_TYPE,
            Self::URI         => URI::RR_TYPE,
            Self::Other(o)    => o.type_number(),
        }
    }
}

// This code is really repetitive, I know, I know
