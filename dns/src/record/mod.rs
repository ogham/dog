//! All the DNS record types, as well as how to parse each type.


mod a;
pub use self::a::A;

mod aaaa;
pub use self::aaaa::AAAA;

mod caa;
pub use self::caa::CAA;

mod cname;
pub use self::cname::CNAME;

mod hinfo;
pub use self::hinfo::HINFO;

mod mx;
pub use self::mx::MX;

mod ns;
pub use self::ns::NS;

mod opt;
pub use self::opt::OPT;

mod ptr;
pub use self::ptr::PTR;

mod soa;
pub use self::soa::SOA;

mod srv;
pub use self::srv::SRV;

mod txt;
pub use self::txt::TXT;


mod others;
pub use self::others::{UnknownQtype, find_other_qtype_number};


/// A record that’s been parsed from a byte buffer.
#[derive(PartialEq, Debug)]
pub enum Record {

    /// An **A** record.
    A(A),

    /// An **AAAA** record.
    AAAA(AAAA),

    /// A **CAA** record.
    CAA(CAA),

    /// A **CNAME** record.
    CNAME(CNAME),

    /// A **HINFO** record.
    HINFO(HINFO),

    /// A **MX** record.
    MX(MX),

    /// A **NS** record.
    NS(NS),

    // OPT is not included here.

    /// A **PTR** record.
    PTR(PTR),

    /// A **SOA** record.
    SOA(SOA),

    /// A **SRV** record.
    SRV(SRV),

    /// A **TXT** record.
    TXT(TXT),

    /// A record with a type that we don’t recognise.
    Other {

        /// The number that’s meant to represent the record type.
        type_number: UnknownQtype,

        /// The undecodable bytes that were in this record.
        bytes: Vec<u8>,
    },
}
