use std::fmt;

use log::*;

use crate::wire::*;


/// A **LOC** _(location)_ record, which points to a location on Earth using
/// its latitude, longitude, and altitude.
///
/// # References
///
/// - [RFC 1876](https://tools.ietf.org/html/rfc1876) — A Means for Expressing Location Information in the Domain Name System (January 1996)
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct LOC {

    /// The diameter of a sphere enclosing the entity at the location, as a
    /// measure of its size, measured in centimetres.
    pub size: Size,

    /// The diameter of the “circle of error” that this location could be in,
    /// measured in centimetres.
    pub horizontal_precision: u8,

    /// The amount of vertical space that this location could be in, measured
    /// in centimetres.
    pub vertical_precision: u8,

    /// The latitude of the centre of the sphere, measured in thousandths of
    /// an arcsecond, positive or negative with 2^31 as the equator.
    pub latitude: u32,

    /// The longitude of the centre of the sphere, measured in thousandths of
    /// an arcsecond, positive or negative with 2^31 as the prime meridian.
    pub longitude: u32,

    /// The altitude of the centre of the sphere, measured in centimetres
    /// above a base of 100,000 metres below the GPS reference spheroid.
    pub altitude: u32,
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Size {
    base: u8,
    power_of_ten: u8,
}


impl Wire for LOC {
    const NAME: &'static str = "LOC";
    const RR_TYPE: u16 = 29;

    #[cfg_attr(all(test, feature = "with_mutagen"), ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length != 16 {
            return Err(WireError::WrongRecordLength { stated_length, mandated_length: 16 });
        }

        let version = c.read_u8()?;
        trace!("Parsed version -> {:?}", version);

        if version != 0 {
            warn!("LOC version is not 0");
        }

        let size_bits = c.read_u8()?;
        trace!("Parsed size bits -> {:#08b}", size_bits);

        let base = size_bits >> 4;
        let power_of_ten = size_bits & 0b_0000_1111;
        trace!("Split size into base {:?} and power of ten {:?}", base, power_of_ten);
        let size = Size { base, power_of_ten };

        let horizontal_precision = c.read_u8()?;
        trace!("Parsed horizontal precision -> {:?}", horizontal_precision);

        let vertical_precision = c.read_u8()?;
        trace!("Parsed vertical precision -> {:?}", vertical_precision);

        let latitude = c.read_u32::<BigEndian>()?;
        trace!("Parsed latitude -> {:?}", version);

        let longitude = c.read_u32::<BigEndian>()?;
        trace!("Parsed longitude -> {:?}", longitude);

        let altitude = c.read_u32::<BigEndian>()?;
        trace!("Parsed altitude -> {:?}", altitude);

        Ok(Self {
            size, horizontal_precision, vertical_precision, latitude, longitude, altitude,
        })
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}e{}", self.base, self.power_of_ten)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses() {
        let buf = &[
            0x00,  // version
            0x32,  // size,
            0x00,  // horizontal precision
            0x00,  // vertical precision
            0x8b, 0x0d, 0x2c, 0x8c,  // latitude
            0x7f, 0xf8, 0xfc, 0xa5,  // longitude
            0x00, 0x98, 0x96, 0x80,  // altitude
        ];

        assert_eq!(LOC::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   LOC {
                       size: Size { base: 3, power_of_ten: 2 },
                       horizontal_precision: 0,
                       vertical_precision: 0,
                       latitude:  0x_8b_0d_2c_8c,
                       longitude: 0x_7f_f8_fc_a5,
                       altitude:  0x_00_98_96_80,
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00,  // version
            0x00,  // size
        ];

        assert_eq!(LOC::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 2, mandated_length: 16 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(LOC::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: 16 }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00,  // version
        ];

        assert_eq!(LOC::read(16, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
