use crate::strings::ReadLabels;
use crate::wire::*;

use log::{warn, debug};


/// A **SOA** _(start of authority)_ record, which contains administrative
/// information about the zone the domain is in. These are returned when a
/// server does not have a record for a domain.
///
/// # References
///
/// - [RFC 1035 §3.3.13](https://tools.ietf.org/html/rfc1035) — Domain Names, Implementation and Specification (November 1987)
#[derive(PartialEq, Debug, Clone)]
pub struct SOA {

    /// The primary master name for this server.
    pub mname: String,

    /// The e-mail address of the administrator responsible for this DNS zone.
    pub rname: String,

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

    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let mname = c.read_labels()?;
        let rname = c.read_labels()?;

        let serial           = c.read_u32::<BigEndian>()?;
        let refresh_interval = c.read_u32::<BigEndian>()?;
        let retry_interval   = c.read_u32::<BigEndian>()?;
        let expire_limit     = c.read_u32::<BigEndian>()?;
        let minimum_ttl      = c.read_u32::<BigEndian>()?;

        let got_length = mname.len() + rname.len() + 4 * 5 + 2;
        if got_length == len as usize {
            debug!("Length {} is correct", len);
        }
        else {
            warn!("Expected length {} but got {}", len, got_length);
        }

        Ok(SOA {
            mname, rname, serial, refresh_interval,
            retry_interval, expire_limit, minimum_ttl,
        })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65, 0x00,
            0x05, 0x62, 0x73, 0x61, 0x67, 0x6f, 0x02, 0x6d, 0x65, 0x00,
            0x5d, 0x3c, 0xef, 0x02,
            0x00, 0x01, 0x51, 0x80,
            0x00, 0x00, 0x1c, 0x20,
            0x00, 0x09, 0x3a, 0x80,
            0x00, 0x00, 0x01, 0x2c,
        ];

        assert_eq!(SOA::read(40, &mut Cursor::new(buf)).unwrap(),
                   SOA {
                       mname: String::from("bsago.me."),
                       rname: String::from("bsago.me."),
                       serial: 1564274434,
                       refresh_interval: 86400,
                       retry_interval: 7200,
                       expire_limit: 604800,
                       minimum_ttl: 300,
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(SOA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}
