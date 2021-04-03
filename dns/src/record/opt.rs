use std::convert::TryFrom;
use std::io;

use log::*;

use crate::wire::*;


/// A **OPT** _(options)_ pseudo-record, which is used to extend the DNS
/// protocol with additional flags such as DNSSEC stuff.
///
/// # Pseudo-record?
///
/// Unlike all the other record types, which are used to return data about a
/// domain name, the OPT record type is used to add more options to the
/// request, including data about the client or the server. It can exist, with
/// a payload, as a query or a response, though it’s usually encountered in
/// the Additional section. Its purpose is to add more room to the DNS wire
/// format, as backwards compatibility makes it impossible to simply add more
/// flags to the header.
///
/// The fact that this isn’t a standard record type is annoying for a DNS
/// implementation. It re-purposes the ‘class’ and ‘TTL’ fields of the
/// `Answer` struct, as they only have meaning when associated with a domain
/// name. This means that the parser has to treat the OPT type specially,
/// switching to `Opt::read` as soon as the rtype is detected. It also means
/// the output has to deal with missing classes and TTLs.
///
/// # References
///
/// - [RFC 6891](https://tools.ietf.org/html/rfc6891) — Extension Mechanisms
///   for DNS (April 2013)
#[derive(PartialEq, Debug, Clone)]
pub struct OPT {

    /// The maximum size of a UDP packet that the client supports.
    pub udp_payload_size: u16,

    /// The bits that form an extended rcode when non-zero.
    pub higher_bits: u8,

    /// The version number of the DNS extension mechanism.
    pub edns0_version: u8,

    /// Sixteen bits worth of flags.
    pub flags: u16,

    /// The payload of the OPT record.
    pub data: Vec<u8>,
}

impl OPT {

    /// The record type number associated with OPT.
    pub const RR_TYPE: u16 = 41;

    /// Reads from the given cursor to parse an OPT record.
    ///
    /// The buffer will have slightly more bytes to read for an OPT record
    /// than for a typical one: we will not have encountered the ‘class’ or
    /// ‘ttl’ fields, which have different meanings for this record type.
    /// See §6.1.3 of the RFC, “OPT Record TTL Field Use”.
    ///
    /// Unlike the `Wire::read` function, this does not require a length.
    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    pub fn read(c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let udp_payload_size = c.read_u16::<BigEndian>()?;  // replaces the class field
        trace!("Parsed UDP payload size -> {:?}", udp_payload_size);

        let higher_bits = c.read_u8()?;  // replaces the ttl field...
        trace!("Parsed higher bits -> {:#08b}", higher_bits);

        let edns0_version = c.read_u8()?;  // ...as does this...
        trace!("Parsed EDNS(0) version -> {:?}", edns0_version);

        let flags = c.read_u16::<BigEndian>()?;  // ...as does this
        trace!("Parsed flags -> {:#08b}", flags);

        let data_length = c.read_u16::<BigEndian>()?;
        trace!("Parsed data length -> {:?}", data_length);

        let mut data = vec![0_u8; usize::from(data_length)];
        c.read_exact(&mut data)?;
        trace!("Parsed data -> {:#x?}", data);

        Ok(Self { udp_payload_size, higher_bits, edns0_version, flags, data })
    }

    /// Serialises this OPT record into a vector of bytes.
    ///
    /// This is necessary for OPT records to be sent in the Additional section
    /// of requests.
    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(32);

        bytes.write_u16::<BigEndian>(self.udp_payload_size)?;
        bytes.write_u8(self.higher_bits)?;
        bytes.write_u8(self.edns0_version)?;
        bytes.write_u16::<BigEndian>(self.flags)?;

        // We should not be sending any data at all in the request, really,
        // so sending too much data is downright nonsensical
        let data_len = u16::try_from(self.data.len()).expect("Sending too much data");
        bytes.write_u16::<BigEndian>(data_len)?;

        for b in &self.data {
            bytes.write_u8(*b)?;
        }

        Ok(bytes)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_no_data() {
        let buf = &[
            0x05, 0xAC,  // UDP payload size
            0x00,        // higher bits
            0x00, 0x00,  // EDNS(0) version
            0x00, 0x00,  // flags
            0x00,        // data length (followed by no data)
        ];

        assert_eq!(OPT::read(&mut Cursor::new(buf)).unwrap(),
                   OPT {
                       udp_payload_size: 1452,
                       higher_bits: 0,
                       edns0_version: 0,
                       flags: 0,
                       data: vec![],
                   });
    }

    #[test]
    fn parses_with_data() {
        let buf = &[
            0x05, 0xAC,  // UDP payload size
            0x00,        // higher bits
            0x00, 0x00,  // EDNS(0) version
            0x00, 0x00,  // flags
            0x04,        // data length
            0x01, 0x02, 0x03, 0x04,  // data
        ];

        assert_eq!(OPT::read(&mut Cursor::new(buf)).unwrap(),
                   OPT {
                       udp_payload_size: 1452,
                       higher_bits: 0,
                       edns0_version: 0,
                       flags: 0,
                       data: vec![1, 2, 3, 4],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(OPT::read(&mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x05,  // half a UDP payload size
        ];

        assert_eq!(OPT::read(&mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
