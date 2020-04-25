use crate::strings::ReadLabels;
use crate::wire::*;

use log::{warn, debug};


/// A **NS** _(name server)_ record, which is used to point domains to name
/// servers.
///
/// # References
///
/// - [RFC 1035 §3.3.11](https://tools.ietf.org/html/rfc1035) — Domain Names, Implementation and Specification (November 1987)
#[derive(PartialEq, Debug, Clone)]
pub struct NS {

    /// The address of a nameserver that provides this DNS response.
    pub nameserver: String,
}

impl Wire for NS {
    const NAME: &'static str = "NS";
    const RR_TYPE: u16 = 2;

    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let nameserver = c.read_labels()?;

        if nameserver.len() + 1 != len as usize {
            warn!("Expected length {} but read {} bytes", len, nameserver.len() + 1);
        }
        else {
            debug!("Length {} is correct", nameserver.len() + 1);
        }

        Ok(NS { nameserver })
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[ 0x01, 0x61, 0x0c, 0x67,
                     0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76,
                     0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, ];

        assert_eq!(NS::read(20, &mut Cursor::new(buf)).unwrap(),
                   NS {
                       nameserver: String::from("a.gtld-servers.net."),
                   });
    }

    #[test]
    fn empty() {
        assert_eq!(NS::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }
}
