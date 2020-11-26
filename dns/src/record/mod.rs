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

    /// A **LOC** record.
    LOC(LOC),

    /// A **MX** record.
    MX(MX),

    /// A **NAPTR** record.
    NAPTR(NAPTR),

    /// A **NS** record.
    NS(NS),

    /// An **OPENPGPKEY** record.
    OPENPGPKEY(OPENPGPKEY),

    // OPT is not included here.

    /// A **PTR** record.
    PTR(PTR),

    /// A **SSHFP** record.
    SSHFP(SSHFP),

    /// A **SOA** record.
    SOA(SOA),

    /// A **SRV** record.
    SRV(SRV),

    /// A **TLSA** record.
    TLSA(TLSA),

    /// A **TXT** record.
    TXT(TXT),

    /// A **URI** record.
    URI(URI),

    /// A record with a type that we don’t recognise.
    Other {

        /// The number that’s meant to represent the record type.
        type_number: UnknownQtype,

        /// The undecodable bytes that were in this record.
        bytes: Vec<u8>,
    },
}
