//! Parsing the DNS wire protocol.

pub(crate) use std::io::{Cursor, Read};
pub(crate) use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

use std::io;
use log::*;

use crate::record::{Record, RecordType, OPT};
use crate::strings::{Labels, ReadLabels, WriteLabels};
use crate::types::*;


impl Request {

    /// Converts this request to a vector of bytes.
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(32);

        bytes.extend_from_slice(&self.transaction_id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_u16().to_be_bytes());

        // One query, no answers or authorities, and the OPT record if any.
        let additional_count = u16::from(self.additional.is_some());
        for count in [ 1, 0, 0, additional_count ] {
            bytes.extend_from_slice(&u16::to_be_bytes(count));
        }

        bytes.write_labels(&self.query.qname)?;
        bytes.extend_from_slice(&self.query.qtype.type_number().to_be_bytes());
        bytes.extend_from_slice(&self.query.qclass.to_u16().to_be_bytes());

        if let Some(opt) = &self.additional {
            bytes.push(0);  // the root name
            bytes.extend_from_slice(&OPT::RR_TYPE.to_be_bytes());
            bytes.extend(opt.to_bytes()?);
        }

        Ok(bytes)
    }

    /// Returns the OPT record to be sent as part of requests.
    pub fn additional_record() -> OPT {
        OPT {
            udp_payload_size: 512,
            higher_bits: 0,
            edns0_version: 0,
            flags: 0,
            data: Vec::new(),
        }
    }
}


impl Response {

    /// Reads bytes off of the given slice, parsing them into a response.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        info!("Parsing response");
        trace!("Bytes -> {bytes:?}");
        let mut c = Cursor::new(bytes);

        let transaction_id = c.read_u16::<BigEndian>()?;
        trace!("Read txid -> {transaction_id:?}");

        let flag_bits = c.read_u16::<BigEndian>()?;
        let mut flags = Flags::from_u16(flag_bits);
        trace!("Read flags -> {flags:#?}");

        let [ query_count, answer_count, authority_count, additional_count ] = read_counts(&mut c)?;

        let queries     = read_section(&mut c, query_count,      "query",             Query::from_bytes)?;
        let answers     = read_section(&mut c, answer_count,     "answer",            Answer::from_bytes)?;
        let authorities = read_section(&mut c, authority_count,  "authority",         Answer::from_bytes)?;
        let additionals = read_section(&mut c, additional_count, "additional answer", Answer::from_bytes)?;

        if let Some(rcode) = extended_rcode(flag_bits, &additionals) {
            flags.error_code = ErrorCode::from_bits(rcode);
        }

        Ok(Self { transaction_id, flags, queries, answers, authorities, additionals })
    }
}

/// Reads the four section counts that follow the flags in the header.
fn read_counts(c: &mut Cursor<&[u8]>) -> Result<[u16; 4], WireError> {
    Ok([
        c.read_u16::<BigEndian>()?,
        c.read_u16::<BigEndian>()?,
        c.read_u16::<BigEndian>()?,
        c.read_u16::<BigEndian>()?,
    ])
}

/// Reads one section of a response: `count` entries, each starting with a
/// name, the rest read by `read_entry`.
fn read_section<T>(
    c: &mut Cursor<&[u8]>,
    count: u16,
    what: &str,
    read_entry: fn(Labels, &mut Cursor<&[u8]>) -> Result<T, WireError>,
) -> Result<Vec<T>, WireError> {

    // The vector can be pre-allocated from the count. But because the count
    // is attacker-controlled (up to 2^16 - 1), it cannot be trusted
    // _entirely_, so cap the pre-allocation if it looks arbitrarily large
    // (9 seems about right).
    let mut entries = Vec::with_capacity(usize::from(count.min(9)));
    debug!("Reading {count}x {what} from response");

    for _ in 0 .. count {
        let (qname, _) = c.read_labels()?;
        entries.push(read_entry(qname, c)?);
    }

    Ok(entries)
}

/// The full twelve-bit response code, when an OPT record extends the four
/// bits in the header with eight more (RFC 6891 §6.1.3).
fn extended_rcode(flag_bits: u16, additionals: &[Answer]) -> Option<u16> {
    additionals.iter().find_map(|answer| match answer {
        Answer::Pseudo { opt, .. }  => Some((u16::from(opt.higher_bits) << 4) | (flag_bits & 0b_1111)),
        Answer::Standard { .. }     => None,
    })
}


impl Query {

    /// Reads bytes from the given cursor, and parses them into a query with
    /// the given domain name.
    fn from_bytes(qname: Labels, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let qtype_number = c.read_u16::<BigEndian>()?;
        trace!("Read qtype number -> {qtype_number:?}" );

        let qtype = RecordType::from(qtype_number);
        trace!("Found qtype -> {qtype:?}" );

        let qclass = QClass::from_u16(c.read_u16::<BigEndian>()?);
        trace!("Read qclass -> {qtype:?}");

        Ok(Self { qname, qclass, qtype })
    }
}


impl Answer {

    /// Reads bytes from the given cursor, and parses them into an answer with
    /// the given domain name.
    fn from_bytes(qname: Labels, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let qtype_number = c.read_u16::<BigEndian>()?;
        trace!("Read qtype number -> {qtype_number:?}" );

        if qtype_number == OPT::RR_TYPE {
            let opt = OPT::read(c)?;
            Ok(Self::Pseudo { qname, opt })
        }
        else {
            let qtype = RecordType::from(qtype_number);
            trace!("Found qtype -> {qtype:?}" );

            let qclass = QClass::from_u16(c.read_u16::<BigEndian>()?);
            trace!("Read qclass -> {qtype:?}");

            let ttl = c.read_u32::<BigEndian>()?;
            trace!("Read TTL -> {ttl:?}");

            let record_length = c.read_u16::<BigEndian>()?;
            trace!("Read record length -> {record_length:?}");

            let record = Record::from_bytes(qtype, record_length, c)?;
            Ok(Self::Standard { qclass, qname, record, ttl })
        }
    }
}


impl Record {

    /// Reads at most `len` bytes from the given curser, and parses them into
    /// a record structure depending on the type number, which has already been read.
    fn from_bytes(record_type: RecordType, len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        macro_rules! read_record {
            ($record:tt) => { {
                info!("Parsing {} record (type {}, len {})", crate::record::$record::NAME, record_type.type_number(), len);
                Wire::read(len, c).map(Self::$record)
            } }
        }

        match record_type {
            RecordType::A           => read_record!(A),
            RecordType::AAAA        => read_record!(AAAA),
            RecordType::CAA         => read_record!(CAA),
            RecordType::CNAME       => read_record!(CNAME),
            RecordType::DNSKEY      => read_record!(DNSKEY),
            RecordType::DS          => read_record!(DS),
            RecordType::EUI48       => read_record!(EUI48),
            RecordType::EUI64       => read_record!(EUI64),
            RecordType::HINFO       => read_record!(HINFO),
            RecordType::LOC         => read_record!(LOC),
            RecordType::MX          => read_record!(MX),
            RecordType::NAPTR       => read_record!(NAPTR),
            RecordType::NS          => read_record!(NS),
            RecordType::NSEC        => read_record!(NSEC),
            RecordType::OPENPGPKEY  => read_record!(OPENPGPKEY),
            RecordType::PTR         => read_record!(PTR),
            RecordType::RRSIG       => read_record!(RRSIG),
            RecordType::SSHFP       => read_record!(SSHFP),
            RecordType::SOA         => read_record!(SOA),
            RecordType::SRV         => read_record!(SRV),
            RecordType::TLSA        => read_record!(TLSA),
            RecordType::TXT         => read_record!(TXT),
            RecordType::URI         => read_record!(URI),
            RecordType::Other(type_number) => Ok(Self::Other { type_number, bytes: read_bytes(len, c)? }),
        }
    }
}

/// Reads exactly `len` bytes.
fn read_bytes(len: u16, c: &mut Cursor<&[u8]>) -> Result<Vec<u8>, WireError> {
    let mut bytes = vec![0_u8; usize::from(len)];
    c.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Reads a `<character-string>` (RFC 1035 §3.3): a length byte, then that
/// many bytes. Returns the bytes, and how many bytes were read in total,
/// counting the length byte.
pub(crate) fn read_character_string(c: &mut Cursor<&[u8]>) -> Result<(Box<[u8]>, u16), WireError> {
    let length = c.read_u8()?;
    let mut bytes = vec![0_u8; usize::from(length)].into_boxed_slice();
    c.read_exact(&mut bytes)?;
    Ok((bytes, 1 + u16::from(length)))
}

/// Bytes as lowercase hexadecimal, two digits each.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0xF)]));
    }
    text
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hexadecimal() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[ 0x00, 0x0f, 0xa0, 0xff ]), "000fa0ff");
    }
}


impl QClass {

    /// The class with this number, by name if it has one. A class given as
    /// a number must go through this, or it would not be equal to the same
    /// class read from a response.
    pub fn from_u16(uu: u16) -> Self {
        match uu {
            0x0001 => Self::IN,
            0x0003 => Self::CH,
            0x0004 => Self::HS,
                 _ => Self::Other(uu),
        }
    }

    fn to_u16(self) -> u16 {
        match self {
            Self::IN        => 0x0001,
            Self::CH        => 0x0003,
            Self::HS        => 0x0004,
            Self::Other(uu) => uu,
        }
    }
}


impl Flags {

    /// The set of flags that represents a query packet.
    pub fn query() -> Self {
        Self::from_u16(0b_0000_0001_0000_0000)
    }

    /// The set of flags that represents a successful response.
    pub fn standard_response() -> Self {
        Self::from_u16(0b_1000_0001_1000_0000)
    }

    /// Converts the flags into a two-byte number. The response code is not
    /// included: dog only ever encodes queries.
    pub fn to_u16(self) -> u16 {                 // 0123 4567 89AB CDEF
        let mut                          bits  = 0b_0000_0000_0000_0000;
        if self.response               { bits |= 0b_1000_0000_0000_0000; }
        bits |= u16::from(self.opcode.to_bits()) << 11;
        if self.authoritative          { bits |= 0b_0000_0100_0000_0000; }
        if self.truncated              { bits |= 0b_0000_0010_0000_0000; }
        if self.recursion_desired      { bits |= 0b_0000_0001_0000_0000; }
        if self.recursion_available    { bits |= 0b_0000_0000_1000_0000; }
        // (the Z bit is reserved)               0b_0000_0000_0100_0000
        if self.authentic_data         { bits |= 0b_0000_0000_0010_0000; }
        if self.checking_disabled      { bits |= 0b_0000_0000_0001_0000; }

        bits
    }

    /// Extracts the flags from the given two-byte number.
    pub fn from_u16(bits: u16) -> Self {
        let has_bit = |bit| { bits & bit == bit };

        Self {
            response:               has_bit(0b_1000_0000_0000_0000),
            opcode:                 Opcode::from_bits((bits.to_be_bytes()[0] & 0b_0111_1000) >> 3),
            authoritative:          has_bit(0b_0000_0100_0000_0000),
            truncated:              has_bit(0b_0000_0010_0000_0000),
            recursion_desired:      has_bit(0b_0000_0001_0000_0000),
            recursion_available:    has_bit(0b_0000_0000_1000_0000),
            authentic_data:         has_bit(0b_0000_0000_0010_0000),
            checking_disabled:      has_bit(0b_0000_0000_0001_0000),
            error_code:             ErrorCode::from_bits(bits & 0b_1111),
        }
    }
}


impl Opcode {

    /// Extracts the opcode from the four bits it occupies in the header.
    /// Higher bits are ignored.
    fn from_bits(bits: u8) -> Self {
        match bits & 0b_1111 {
            0     => Self::Query,
            other => Self::Other(other),
        }
    }

    /// The four bits this opcode occupies in the header.
    fn to_bits(self) -> u8 {
        match self {
            Self::Query     => 0,
            Self::Other(n)  => n & 0b_1111,
        }
    }
}


impl ErrorCode {

    /// Interprets a response code: the four bits of the header, or the
    /// twelve bits of an extended response code.
    fn from_bits(bits: u16) -> Option<Self> {
        if (0x0F01 ..= 0x0FFF).contains(&bits) {
            return Some(Self::Private(bits));
        }

        match bits {
            0 => None,
            1 => Some(Self::FormatError),
            2 => Some(Self::ServerFailure),
            3 => Some(Self::NXDomain),
            4 => Some(Self::NotImplemented),
            5 => Some(Self::QueryRefused),
           16 => Some(Self::BadVersion),
            n => Some(Self::Other(n)),
        }
    }
}


/// Trait for decoding DNS record structures from bytes read over the wire.
pub trait Wire: Sized {

    /// This record’s type as a string, such as `"A"` or `"CNAME"`.
    const NAME: &'static str;

    /// The number signifying that a record is of this type.
    /// See <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>
    const RR_TYPE: u16;

    /// Read at most `len` bytes from the given `Cursor`. This cursor travels
    /// throughout the complete data — by this point, we have read the entire
    /// response into a buffer.
    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError>;
}


/// Something that can go wrong deciphering a record.
#[derive(PartialEq, Debug)]
pub enum WireError {

    /// There was an IO error reading from the cursor.
    /// Almost all the time, this means that the buffer was too short.
    IO,
    // (io::Error is not PartialEq so we don’t propagate it)

    /// When the DNS standard requires records of this type to have a certain
    /// fixed length, but the response specified a different length.
    ///
    /// This error should be returned regardless of the _content_ of the
    /// record, whatever it is.
    WrongRecordLength {

        /// The length of the record’s data, as specified in the packet.
        stated_length: u16,

        /// The length of the record that the DNS specification mandates.
        mandated_length: MandatedLength,
    },

    /// When the length of this record as specified in the packet differs from
    /// the computed length, as determined by reading labels.
    ///
    /// There are two ways, in general, to read arbitrary-length data from a
    /// stream of bytes: length-prefixed (read the length, then read that many
    /// bytes) or sentinel-terminated (keep reading bytes until you read a
    /// certain value, usually zero). The DNS protocol uses both: each
    /// record’s size is specified up-front in the packet, but inside the
    /// record, there exist arbitrary-length strings that must be read until a
    /// zero is read, indicating there is no more string.
    ///
    /// Consider the case of a packet, with a specified length, containing a
    /// string of arbitrary length (such as the CNAME or TXT records). A DNS
    /// client has to deal with this in one of two ways:
    ///
    /// 1. Read exactly the specified length of bytes from the record, raising
    ///    an error if the contents are too short or a string keeps going past
    ///    the length (assume the length is correct but the contents are wrong).
    ///
    /// 2. Read as many bytes from the record as the string requests, raising
    ///    an error if the number of bytes read at the end differs from the
    ///    expected length of the record (assume the length is wrong but the
    ///    contents are correct).
    ///
    /// Note that no matter which way is picked, the record will still be
    /// incorrect — it only impacts the parsing of records that occur after it
    /// in the packet. Knowing which method should be used requires knowing
    /// what caused the DNS packet to be erroneous, which we cannot know.
    ///
    /// dog picks the second way. If a record ends up reading more or fewer
    /// bytes than it is ‘supposed’ to, it will raise this error, but _after_
    /// having read a different number of bytes than the specified length.
    WrongLabelLength {

        /// The length of the record’s data, as specified in the packet.
        stated_length: u16,

        /// The computed length of the record’s data, based on the number of
        /// bytes consumed by reading labels from the packet.
        length_after_labels: u16,
    },

    /// When the data contained a string containing a cycle of pointers.
    /// Contains the vector of indexes that was being checked.
    TooMuchRecursion(Box<[u16]>),

    /// When the data contained a string with a pointer to an index outside of
    /// the packet. Contains the invalid index.
    OutOfBounds(u16),

    /// When a record in the packet contained a version field that specifies
    /// the format of its remaining fields, but this version is too recent to
    /// be supported, so we cannot parse it.
    WrongVersion {

        /// The version of the record layout, as specified in the packet
        stated_version: u8,

        /// The maximum version that this version of dog supports.
        maximum_supported_version: u8,
    }
}

/// The rule for how long a record in a packet should be.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum MandatedLength {

    /// The record should be exactly this many bytes in length.
    Exactly(u16),

    /// The record should be _at least_ this many bytes in length.
    AtLeast(u16),
}

impl From<io::Error> for WireError {
    fn from(ioe: io::Error) -> Self {
        error!("IO error -> {ioe:?}");
        Self::IO
    }
}
