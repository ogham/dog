use log::*;

use crate::wire::*;


/// A **TLSA** _(TLS authentication)_ record, which contains a TLS certificate
/// (or a public key, or its hash), associating it with a domain.
///
/// # References
///
/// - [RFC 6698](https://tools.ietf.org/html/rfc6698) — The DNS-Based
///   Authentication of Named Entities (DANE) Transport Layer Security
///   Protocol: TLSA (August 2012)
#[derive(PartialEq, Debug)]
pub struct TLSA {

    /// A number representing the purpose of the certificate.
    pub certificate_usage: u8,

    /// A number representing which part of the certificate is returned in the
    /// data. This could be the full certificate, or just the public key.
    pub selector: u8,

    /// A number representing whether a certificate should be associated with
    /// the exact data, or with a hash of it.
    pub matching_type: u8,

    /// A series of bytes representing the certificate.
    pub certificate_data: Vec<u8>,
}


impl Wire for TLSA {
    const NAME: &'static str = "TLSA";
    const RR_TYPE: u16 = 52;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {

        let certificate_usage = c.read_u8()?;
        trace!("Parsed certificate_usage -> {:?}", certificate_usage);

        let selector = c.read_u8()?;
        trace!("Parsed selector -> {:?}", selector);

        let matching_type = c.read_u8()?;
        trace!("Parsed matching type -> {:?}", matching_type);

        if stated_length <= 3 {
            let mandated_length = MandatedLength::AtLeast(4);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let certificate_data_length = stated_length - 1 - 1 - 1;
        let mut certificate_data = vec![0_u8; usize::from(certificate_data_length)];
        c.read_exact(&mut certificate_data)?;
        trace!("Parsed fingerprint -> {:#x?}", certificate_data);

        Ok(Self { certificate_usage, selector, matching_type, certificate_data })
    }
}

impl TLSA {

    /// Returns the hexadecimal representation of the fingerprint.
    pub fn hex_certificate_data(&self) -> String {
        self.certificate_data.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x03,  // certificate usage
            0x01,  // selector
            0x01,  // matching type
            0x05, 0x95, 0x98, 0x11, 0x22, 0x33 // data
        ];

        assert_eq!(TLSA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   TLSA {
                       certificate_usage: 3,
                       selector: 1,
                       matching_type: 1,
                       certificate_data: vec![ 0x05, 0x95, 0x98, 0x11, 0x22, 0x33 ],
                   });
    }

    #[test]
    fn one_byte_certificate() {
        let buf = &[
            0x03,  // certificate usage
            0x01,  // selector
            0x01,  // matching type
            0x05,  // one byte of data
        ];

        assert_eq!(TLSA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   TLSA {
                       certificate_usage: 3,
                       selector: 1,
                       matching_type: 1,
                       certificate_data: vec![ 0x05 ],
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x03,  // certificate usage
            0x01,  // selector
            0x01,  // matching type
        ];

        assert_eq!(TLSA::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 3, mandated_length: MandatedLength::AtLeast(4) }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(TLSA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x01,  // certificate_usage
        ];

        assert_eq!(TLSA::read(6, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}

