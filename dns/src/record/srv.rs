use crate::strings::ReadLabels;
use crate::wire::*;

use log::{debug, warn};


/// A **SRV** record, which contains an IP address as well as a port number,
/// for specifying the location of services more precisely.
///
/// # References
///
/// - [RFC 2782](https://tools.ietf.org/html/rfc2782) — A DNS RR for specifying the location of services (February 2000)
#[derive(PartialEq, Debug, Clone)]
pub struct SRV {

    /// The priority of this host among all that get returned. Lower values
    /// are higher priority.
    pub priority: u16,

    /// A weight to choose among results with the same priority. Higher values
    /// are higher priority.
    pub weight: u16,

    /// The port the service is serving on.
    pub port: u16,

    /// The hostname of the machine the service is running on.
    pub target: String,
}

impl Wire for SRV {
    const NAME: &'static str = "SRV";
    const RR_TYPE: u16 = 33;

    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let priority = c.read_u16::<BigEndian>()?;
        let weight   = c.read_u16::<BigEndian>()?;
        let port     = c.read_u16::<BigEndian>()?;
        let target   = c.read_labels()?;

        let got_length = 3 * 2 + target.len() + 1;
        if got_length != len as usize {
            warn!("Expected length {} but got {}", len, got_length);
        }
        else {
            debug!("Length {} is correct", len);
        }

        Ok(SRV { priority, weight, port, target })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[ 0x00, 0x01, 0x00, 0x01, 0x92, 0x7c, 0x03, 0x61, 0x74,
                     0x61, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x04, 0x6e,
                     0x6f, 0x64, 0x65, 0x03, 0x64, 0x63, 0x31, 0x06, 0x63,
                     0x6f, 0x6e, 0x73, 0x75, 0x6c, 0x00, ];

        assert_eq!(SRV::read(33, &mut Cursor::new(buf)).unwrap(),
                   SRV {
                       priority: 1,
                       weight: 1,
                       port: 37500,
                       target: String::from("ata.local.node.dc1.consul."),
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(SRV::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}
