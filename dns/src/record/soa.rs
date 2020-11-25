use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// A **SOA** _(start of authority)_ record, which contains administrative
/// information about the zone the domain is in. These are returned when a
/// server does not have a record for a domain.
///
/// # References
///
/// - [RFC 1035 §3.3.13](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
#[derive(PartialEq, Debug)]
pub struct SOA {

    /// The primary master name for this server.
    pub mname: Labels,

    /// The e-mail address of the administrator responsible for this DNS zone.
    pub rname: Labels,

    /// A serial number for this DNS zone.
    pub serial: u32,

    /// Duration, in seconds, after which secondary nameservers should query
    /// the master for _its_ SOA record.
    pub refresh_interval: u32,

    /// Duration, in seconds, after which secondary nameservers should retry
    /// requesting the serial number from the master if it does not respond.
    /// It should be less than `refresh`.
    pub retry_interval: u32,

    /// Duration, in seconds, after which secondary nameservers should stop
    /// answering requests for this zone if the master does not respond.
    /// It should be greater than the sum of `refresh` and `retry`.
    pub expire_limit: u32,

    /// Duration, in seconds, of the minimum time-to-live.
    pub minimum_ttl: u32,
}

impl Wire for SOA {
    const NAME: &'static str = "SOA";
    const RR_TYPE: u16 = 6;

    #[allow(clippy::similar_names)]
    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let (mname, mname_length) = c.read_labels()?;
        trace!("Parsed mname -> {:?}", mname);

        let (rname, rname_length) = c.read_labels()?;
        trace!("Parsed rname -> {:?}", rname);

        let serial = c.read_u32::<BigEndian>()?;
        trace!("Parsed serial -> {:?}", serial);

        let refresh_interval = c.read_u32::<BigEndian>()?;
        trace!("Parsed refresh interval -> {:?}", refresh_interval);

        let retry_interval = c.read_u32::<BigEndian>()?;
        trace!("Parsed retry interval -> {:?}", retry_interval);

        let expire_limit = c.read_u32::<BigEndian>()?;
        trace!("Parsed expire limit -> {:?}", expire_limit);

        let minimum_ttl = c.read_u32::<BigEndian>()?;
        trace!("Parsed minimum TTL -> {:?}", minimum_ttl);

        let length_after_labels = 4 * 5 + mname_length + rname_length;
        if stated_length == length_after_labels {
            trace!("Length is correct");
            Ok(Self {
                mname, rname, serial, refresh_interval,
                retry_interval, expire_limit, minimum_ttl,
            })
        }
        else {
            warn!("Length is incorrect (stated length {:?}, mname plus rname plus fields length {:?})", stated_length, length_after_labels);
            Err(WireError::WrongLabelLength { stated_length, length_after_labels })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65,  // mname
            0x00,  // mname terminator
            0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65,  // rname
            0x00,  // rname terminator
            0x5d, 0x3c, 0xef, 0x02,  // Serial
            0x00, 0x01, 0x51, 0x80,  // Refresh interval
            0x00, 0x00, 0x1c, 0x20,  // Retry interval
            0x00, 0x09, 0x3a, 0x80,  // Expire limit
            0x00, 0x00, 0x01, 0x2c,  // Minimum TTL
        ];

        assert_eq!(SOA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   SOA {
                       mname: Labels::encode("bsago.me").unwrap(),
                       rname: Labels::encode("bsago.me").unwrap(),
                       serial: 1564274434,
                       refresh_interval: 86400,
                       retry_interval: 7200,
                       expire_limit: 604800,
                       minimum_ttl: 300,
                   });
    }

    #[test]
    fn incorrect_record_length() {
        let buf = &[
            0x03, 0x65, 0x66, 0x67,  // mname
            0x00,  // mname terminator
            0x03, 0x65, 0x66, 0x67,  // rname
            0x00,  // rname terminator
            0x5d, 0x3c, 0xef, 0x02,  // Serial
            0x00, 0x01, 0x51, 0x80,  // Refresh interval
            0x00, 0x00, 0x1c, 0x20,  // Retry interval
            0x00, 0x09, 0x3a, 0x80,  // Expire limit
            0x00, 0x00, 0x01, 0x2c,  // Minimum TTL
        ];

        assert_eq!(SOA::read(89, &mut Cursor::new(buf)),
                   Err(WireError::WrongLabelLength { stated_length: 89, length_after_labels: 30 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(SOA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x05, 0x62,  // the start of an mname
        ];

        assert_eq!(SOA::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
