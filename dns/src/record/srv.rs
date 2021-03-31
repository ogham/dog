use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;


/// A **SRV** record, which contains an IP address as well as a port number,
/// for specifying the location of services more precisely.
///
/// # References
///
/// - [RFC 2782](https://tools.ietf.org/html/rfc2782) — A DNS RR for
///   specifying the location of services (February 2000)
#[derive(PartialEq, Debug)]
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
    pub target: Labels,
}

impl Wire for SRV {
    const NAME: &'static str = "SRV";
    const RR_TYPE: u16 = 33;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let priority = c.read_u16::<BigEndian>()?;
        trace!("Parsed priority -> {:?}", priority);

        let weight = c.read_u16::<BigEndian>()?;
        trace!("Parsed weight -> {:?}", weight);

        let port = c.read_u16::<BigEndian>()?;
        trace!("Parsed port -> {:?}", port);

        let (target, target_length) = c.read_labels()?;
        trace!("Parsed target -> {:?}", target);

        let length_after_labels = 3 * 2 + target_length;
        if stated_length == length_after_labels {
            trace!("Length is correct");
            Ok(Self { priority, weight, port, target })
        }
        else {
            warn!("Length is incorrect (stated length {:?}, fields plus target length {:?})", stated_length, length_after_labels);
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
            0x00, 0x01,  // priority
            0x00, 0x01,  // weight
            0x92, 0x7c,  // port
            0x03, 0x61, 0x74, 0x61, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x04,
            0x6e, 0x6f, 0x64, 0x65, 0x03, 0x64, 0x63, 0x31, 0x06, 0x63, 0x6f,
            0x6e, 0x73, 0x75, 0x6c,  // target
            0x00,  // target terminator
        ];

        assert_eq!(SRV::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   SRV {
                       priority: 1,
                       weight: 1,
                       port: 37500,
                       target: Labels::encode("ata.local.node.dc1.consul").unwrap(),
                   });
    }

    #[test]
    fn incorrect_record_length() {
        let buf = &[
            0x00, 0x01,  // priority
            0x00, 0x01,  // weight
            0x92, 0x7c,  // port
            0x03, 0x61, 0x74, 0x61,  // target
            0x00,  // target terminator
        ];

        assert_eq!(SRV::read(16, &mut Cursor::new(buf)),
                   Err(WireError::WrongLabelLength { stated_length: 16, length_after_labels: 11 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(SRV::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00,  // half a priority
        ];

        assert_eq!(SRV::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
