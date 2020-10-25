use crate::strings::ReadLabels;
use crate::wire::*;

use log::*;


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

    #[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
    fn read(len: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let (nameserver, nameserver_len) = c.read_labels()?;
        trace!("Parsed nameserver -> {:?}", nameserver);

        if len == nameserver_len {
            trace!("Length is correct");
            Ok(Self { nameserver })
        }
        else {
            warn!("Length is incorrect (record length {:?}, nameserver length {:?}", len, nameserver_len);
            Err(WireError::WrongLabelLength { expected: len, got: nameserver_len })
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x01, 0x61, 0x0c, 0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72,
            0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74,  // nameserver
            0x00,  // nameserver terminator
        ];

        assert_eq!(NS::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
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
