use log::*;

use crate::wire::*;


/// A (an?) **HINFO** _(host information)_ record, which contains the CPU and
/// OS information about a host.
///
/// It also gets used as the response for an `ANY` query, if it is blocked.
///
/// # References
///
/// - [RFC 1035 §3.3.2](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
/// - [RFC 8482 §6](https://tools.ietf.org/html/rfc8482#section-6) — Providing
///   Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY (January 2019)
#[derive(PartialEq, Debug)]
pub struct HINFO {

    /// The CPU field, specifying the CPU type.
    pub cpu: Box<[u8]>,

    /// The OS field, specifying the operating system.
    pub os: Box<[u8]>,
}

impl Wire for HINFO {
    const NAME: &'static str = "HINFO";
    const RR_TYPE: u16 = 13;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {

        let cpu_length = c.read_u8()?;
        trace!("Parsed CPU length -> {:?}", cpu_length);

        let mut cpu = vec![0_u8; usize::from(cpu_length)].into_boxed_slice();
        c.read_exact(&mut cpu)?;
        trace!("Parsed CPU -> {:?}", String::from_utf8_lossy(&cpu));

        let os_length = c.read_u8()?;
        trace!("Parsed OS length -> {:?}", os_length);

        let mut os = vec![0_u8; usize::from(os_length)].into_boxed_slice();
        c.read_exact(&mut os)?;
        trace!("Parsed OS -> {:?}", String::from_utf8_lossy(&os));

        let length_after_labels = 1 + u16::from(cpu_length) + 1 + u16::from(os_length);
        if stated_length == length_after_labels {
            trace!("Length is correct");
            Ok(Self { cpu, os })
        }
        else {
            warn!("Length is incorrect (stated length {:?}, cpu plus length {:?}", stated_length, length_after_labels);
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
            0x0e,  // cpu length
            0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x6b, 0x69, 0x6e, 0x64, 0x61, 0x2d,
            0x63, 0x70, 0x75,  // cpu
            0x0d,  // os length
            0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x6b, 0x69, 0x6e, 0x64, 0x61, 0x2d,
            0x6f, 0x73,  // os
        ];

        assert_eq!(HINFO::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   HINFO {
                       cpu: Box::new(*b"some-kinda-cpu"),
                       os: Box::new(*b"some-kinda-os"),
                   });
    }

    #[test]
    fn incorrect_record_length() {
        let buf = &[
            0x03,  // cpu length
            0x65, 0x66, 0x67,  // cpu
            0x03,  // os length
            0x68, 0x69, 0x70,  // os
        ];

        assert_eq!(HINFO::read(6, &mut Cursor::new(buf)),
                   Err(WireError::WrongLabelLength { stated_length: 6, length_after_labels: 8 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(HINFO::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x14, 0x0A, 0x0B, 0x0C,  // 32-bit CPU
        ];

        assert_eq!(HINFO::read(23, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
