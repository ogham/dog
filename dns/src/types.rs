//! DNS packets are traditionally implemented with both the request and
//! response packets at the same type. After all, both follow the same format,
//! with the request packet having zero answer fields, and the response packet
//! having at least one record in its answer fields.

use crate::record::{Record, RecordType, OPT};
use crate::strings::Labels;


/// A request that gets sent out over a transport.
#[derive(PartialEq, Debug)]
pub struct Request {

    /// The transaction ID of this request. This is used to make sure
    /// different DNS packets don’t answer each other’s questions.
    pub transaction_id: u16,

    /// The flags that accompany every DNS packet.
    pub flags: Flags,

    /// The query that this request is making. Only one query is allowed per
    /// request, as traditionally, DNS servers only respond to the first query
    /// in a packet.
    pub query: Query,

    /// An additional record that may be sent as part of the query.
    pub additional: Option<OPT>,
}


/// A response obtained from a DNS server.
#[derive(PartialEq, Debug)]
pub struct Response {

    /// The transaction ID, which should match the ID of the request.
    pub transaction_id: u16,

    /// The flags that accompany every DNS packet.
    pub flags: Flags,

    /// The queries section.
    pub queries: Vec<Query>,

    /// The answers section.
    pub answers: Vec<Answer>,

    /// The authoritative nameservers section.
    pub authorities: Vec<Answer>,

    /// The additional records section.
    pub additionals: Vec<Answer>,
}


/// A DNS query section.
#[derive(PartialEq, Debug)]
pub struct Query {

    /// The domain name being queried, in human-readable dotted notation.
    pub qname: Labels,

    /// The class number.
    pub qclass: QClass,

    /// The type number.
    pub qtype: RecordType,
}


/// A DNS answer section.
#[derive(PartialEq, Debug)]
pub enum Answer {

    /// This is a standard answer with every field.
    Standard {

        /// The domain name being answered for.
        qname: Labels,

        /// This answer’s class.
        qclass: QClass,

        /// The time-to-live duration, in seconds.
        ttl: u32,

        /// The record contained in this answer.
        record: Record,
    },

    /// This is a pseudo-record answer, so some of the fields (class and TTL)
    /// have different meaning.
    Pseudo {

        /// The domain name being answered for.
        qname: Labels,

        /// The OPT record contained in this answer.
        opt: OPT,
    },
}


/// A DNS record class. Of these, the only one that’s in regular use anymore
/// is the Internet class.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum QClass {

    /// The **Internet** class.
    IN,

    /// The **Chaosnet** class.
    CH,

    /// The **Hesiod** class.
    HS,

    /// A class number that does not map to any known class.
    Other(u16),
}


/// The flags that accompany every DNS packet.
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Flags {

    /// Whether this packet is a response packet.
    pub response: bool,

    /// The operation being performed.
    pub opcode: Opcode,

    /// In a response, whether the server is providing authoritative DNS responses.
    pub authoritative: bool,

    /// In a response, whether this message has been truncated by the transport.
    pub truncated: bool,

    /// In a query, whether the server may query other nameservers recursively.
    /// It is up to the server whether it will actually do this.
    pub recursion_desired: bool,

    /// In a response, whether the server allows recursive query support.
    pub recursion_available: bool,

    /// In a response, whether the server is marking this data as authentic.
    pub authentic_data: bool,

    /// In a request, whether the server should disable its authenticity
    /// checking for the request’s queries.
    pub checking_disabled: bool,

    /// In a response, a code indicating an error if one occurred.
    pub error_code: Option<ErrorCode>,
}


/// A number representing the operation being performed.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Opcode {

    /// This request is a standard query, or this response is answering a
    /// standard query.
    Query,

    /// Any other opcode. This can be from 1 to 15, as the opcode field is
    /// four bits wide, and 0 is taken.
    Other(u8),
}


/// A code indicating an error.
///
/// # References
///
/// - [RFC 6895 §2.3](https://tools.ietf.org/html/rfc6895#section-2.3) — Domain
///   Name System (DNS) IANA Considerations (April 2013)
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum ErrorCode {

    /// `FormErr` — The server was unable to interpret the query.
    FormatError,

    /// `ServFail` — There was a problem with the server.
    ServerFailure,

    /// `NXDomain` — The domain name referenced in the query does not exist.
    NXDomain,

    /// `NotImp` — The server does not support one of the requested features.
    NotImplemented,

    /// `Refused` — The server was able to interpret the query, but refused to
    /// fulfil it.
    QueryRefused,

    /// `BADVERS` and `BADSIG` — The server did not accept the EDNS version,
    /// or failed to verify a signature. The same code is used for both.
    BadVersion,

    /// An error code with no currently-defined meaning.
    Other(u16),

    /// An error code within the ‘Reserved for Private Use’ range.
    Private(u16)
}


impl Answer {

    /// Whether this Answer holds a standard record, not a pseudo record.
    pub fn is_standard(&self) -> bool {
        matches!(self, Self::Standard { .. })
    }
}
