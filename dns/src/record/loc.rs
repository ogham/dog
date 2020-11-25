use std::fmt;

use log::*;

use crate::wire::*;


/// A **LOC** _(location)_ record, which points to a location on Earth using
/// its latitude, longitude, and altitude.
///
/// # References
///
/// - [RFC 1876](https://tools.ietf.org/html/rfc1876) — A Means for Expressing
///   Location Information in the Domain Name System (January 1996)
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

    /// The latitude of the centre of the sphere. If `None`, the packet
    /// parses, but the position is out of range.
    pub latitude: Option<Position>,

    /// The longitude of the centre of the sphere. If `None`, the packet
    /// parses, but the position is out of range.
    pub longitude: Option<Position>,

    /// The altitude of the centre of the sphere, measured in centimetres
    /// above a base of 100,000 metres below the GPS reference spheroid.
    pub altitude: Altitude,
}

/// A measure of size, in centimetres, represented by a base and an exponent.
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Size {
    base: u8,
    power_of_ten: u8,
}

/// A position on one of the world’s axes.
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Position {
    degrees: u32,
    arcminutes: u32,
    arcseconds: u32,
    milliarcseconds: u32,
    direction: Direction,
}

/// A position on the vertical axis.
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct Altitude {
    metres: i64,
    centimetres: i64,
}

/// One of the directions a position could be in, relative to the equator or
/// prime meridian.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Direction {
    North,
    East,
    South,
    West,
}

impl Wire for LOC {
    const NAME: &'static str = "LOC";
    const RR_TYPE: u16 = 29;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let version = c.read_u8()?;
        trace!("Parsed version -> {:?}", version);

        if version != 0 {
            return Err(WireError::WrongVersion {
                stated_version: version,
                maximum_supported_version: 0,
            });
        }

        if stated_length != 16 {
            let mandated_length = MandatedLength::Exactly(16);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let size_bits = c.read_u8()?;
        let size = Size::from_u8(size_bits);
        trace!("Parsed size -> {:#08b} ({})", size_bits, size);

        let horizontal_precision = c.read_u8()?;
        trace!("Parsed horizontal precision -> {:?}", horizontal_precision);

        let vertical_precision = c.read_u8()?;
        trace!("Parsed vertical precision -> {:?}", vertical_precision);

        let latitude_num = c.read_u32::<BigEndian>()?;
        let latitude = Position::from_u32(latitude_num, true);
        trace!("Parsed latitude -> {:?} ({:?})", latitude_num, latitude);

        let longitude_num = c.read_u32::<BigEndian>()?;
        let longitude = Position::from_u32(longitude_num, false);
        trace!("Parsed longitude -> {:?} ({:?})", longitude_num, longitude);

        let altitude_num = c.read_u32::<BigEndian>()?;
        let altitude = Altitude::from_u32(altitude_num);
        trace!("Parsed altitude -> {:?} ({:})", altitude_num, altitude);

        Ok(Self {
            size, horizontal_precision, vertical_precision, latitude, longitude, altitude,
        })
    }
}

impl Size {

    /// Converts a number into the size it represents. To allow both small and
    /// large sizes, the input octet is split into two four-bit sizes, one the
    /// base, and one the power of ten exponent.
    fn from_u8(input: u8) -> Self {
        let base = input >> 4;
        let power_of_ten = input & 0b_0000_1111;
        Self { base, power_of_ten }
    }
}

impl Position {

    /// Converts a number into the position it represents. The input number is
    /// measured in thousandths of an arcsecond (milliarcseconds), with 2^31
    /// as the equator or prime meridian.
    ///
    /// Returns `None` if the input is out of range, meaning it would wrap
    /// around to another half of the Earth once or more.
    fn from_u32(mut input: u32, vertical: bool) -> Option<Self> {
        let max_for_direction = if vertical { 90 } else { 180 };
        let limit = 1000 * 60 * 60 * max_for_direction;

        if input < (0x_8000_0000 - limit) || input > (0x_8000_0000 + limit) {
            // Input is out of range
            None
        }
        else if input >= 0x_8000_0000 {
            // Input is north or east, so de-relativise it and divide into segments
            input -= 0x_8000_0000;
            let milliarcseconds = input % 1000;
            let total_arcseconds = input / 1000;

            let arcseconds = total_arcseconds % 60;
            let total_arcminutes = total_arcseconds / 60;

            let arcminutes = total_arcminutes % 60;
            let degrees = total_arcminutes / 60;

            let direction = if vertical { Direction::North }
                                   else { Direction::East };

            Some(Self { degrees, arcminutes, arcseconds, milliarcseconds, direction })
        }
        else {
            // Input is south or west, so do the calculations for
            let mut pos = Self::from_u32(input + (0x_8000_0000_u32 - input) * 2, vertical)?;

            pos.direction = if vertical { Direction::South }
                                   else { Direction::West };
            Some(pos)
        }
    }
}

impl Altitude {
    fn from_u32(input: u32) -> Self {
        let mut input = i64::from(input);
        input -= 10_000_000;  // 100,000m
        let metres = input / 100;
        let centimetres = input % 100;
        Self { metres, centimetres }
    }
}


impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}e{}", self.base, self.power_of_ten)
    }
}

impl fmt::Display for Position {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}°{}′{}",
            self.degrees,
            self.arcminutes,
            self.arcseconds,
        )?;

        if self.milliarcseconds != 0 {
            write!(f, ".{:03}", self.milliarcseconds)?;
        }

        write!(f, "″ {}", self.direction)
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::North  => write!(f, "N"),
            Self::East   => write!(f, "E"),
            Self::South  => write!(f, "S"),
            Self::West   => write!(f, "W"),
        }
    }
}

impl fmt::Display for Altitude {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Usually there’s a space between the number and the unit, but
        // spaces are already used to delimit segments in the record summary
        if self.centimetres == 0 {
            write!(f, "{}m", self.metres)
        }
        else {
            write!(f, "{}.{:02}m", self.metres, self.centimetres)
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
                       latitude:  Position::from_u32(0x_8b_0d_2c_8c, true),
                       longitude: Position::from_u32(0x_7f_f8_fc_a5, false),
                       altitude:  Altitude::from_u32(0x_00_98_96_80),
                   });
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x00,  // version
            0x00,  // size
        ];

        assert_eq!(LOC::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 2, mandated_length: MandatedLength::Exactly(16) }));
    }

    #[test]
    fn record_too_long() {
        let buf = &[
            0x00,  // version
            0x32,  // size,
            0x00,  // horizontal precision
            0x00,  // vertical precision
            0x8b, 0x0d, 0x2c, 0x8c,  // latitude
            0x7f, 0xf8, 0xfc, 0xa5,  // longitude
            0x00, 0x98, 0x96, 0x80,  // altitude
            0x12, 0x34, 0x56,  // some other stuff
        ];

        assert_eq!(LOC::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 19, mandated_length: MandatedLength::Exactly(16) }));
    }

    #[test]
    fn more_recent_version() {
        let buf = &[
            0x80,  // version
            0x12, 0x34, 0x56,  // some data in an unknown format
        ];

        assert_eq!(LOC::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongVersion { stated_version: 128, maximum_supported_version: 0 }));
    }

    #[test]
    fn record_empty() {
        assert_eq!(LOC::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
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


#[cfg(test)]
mod size_test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn zeroes() {
        assert_eq!(Size::from_u8(0b_0000_0000).to_string(),
                   String::from("0e0"));
    }

    #[test]
    fn ones() {
        assert_eq!(Size::from_u8(0b_0001_0001).to_string(),
                   String::from("1e1"));
    }

    #[test]
    fn schfourteen_teen() {
        assert_eq!(Size::from_u8(0b_1110_0011).to_string(),
                   String::from("14e3"));
    }

    #[test]
    fn ones_but_bits_this_time() {
        assert_eq!(Size::from_u8(0b_1111_1111).to_string(),
                   String::from("15e15"));
    }
}


#[cfg(test)]
mod position_test {
    use super::*;
    use pretty_assertions::assert_eq;

    // centre line tests

    #[test]
    fn meridian() {
        assert_eq!(Position::from_u32(0x_8000_0000, false).unwrap().to_string(),
                   String::from("0°0′0″ E"));
    }

    #[test]
    fn meridian_plus_one() {
        assert_eq!(Position::from_u32(0x_8000_0000 + 1, false).unwrap().to_string(),
                   String::from("0°0′0.001″ E"));
    }

    #[test]
    fn meridian_minus_one() {
        assert_eq!(Position::from_u32(0x_8000_0000 - 1, false).unwrap().to_string(),
                   String::from("0°0′0.001″ W"));
    }

    #[test]
    fn equator() {
        assert_eq!(Position::from_u32(0x_8000_0000, true).unwrap().to_string(),
                   String::from("0°0′0″ N"));
    }

    #[test]
    fn equator_plus_one() {
        assert_eq!(Position::from_u32(0x_8000_0000 + 1, true).unwrap().to_string(),
                   String::from("0°0′0.001″ N"));
    }

    #[test]
    fn equator_minus_one() {
        assert_eq!(Position::from_u32(0x_8000_0000 - 1, true).unwrap().to_string(),
                   String::from("0°0′0.001″ S"));
    }

    // arbitrary value tests

    #[test]
    fn some_latitude() {
        assert_eq!(Position::from_u32(2332896396, true).unwrap().to_string(),
                   String::from("51°30′12.748″ N"));
    }

    #[test]
    fn some_longitude() {
        assert_eq!(Position::from_u32(2147024037, false).unwrap().to_string(),
                   String::from("0°7′39.611″ W"));
    }

    // limit tests

    #[test]
    fn the_north_pole() {
        assert_eq!(Position::from_u32(0x8000_0000 + (1000 * 60 * 60 * 90), true).unwrap().to_string(),
                   String::from("90°0′0″ N"));
    }

    #[test]
    fn the_north_pole_plus_one() {
        assert_eq!(Position::from_u32(0x8000_0000 + (1000 * 60 * 60 * 90) + 1, true),
                   None);
    }

    #[test]
    fn the_south_pole() {
        assert_eq!(Position::from_u32(0x8000_0000 - (1000 * 60 * 60 * 90), true).unwrap().to_string(),
                   String::from("90°0′0″ S"));
    }

    #[test]
    fn the_south_pole_minus_one() {
        assert_eq!(Position::from_u32(0x8000_0000 - (1000 * 60 * 60 * 90) - 1, true),
                   None);
    }

    #[test]
    fn the_far_east() {
        assert_eq!(Position::from_u32(0x8000_0000 + (1000 * 60 * 60 * 180), false).unwrap().to_string(),
                   String::from("180°0′0″ E"));
    }

    #[test]
    fn the_far_east_plus_one() {
        assert_eq!(Position::from_u32(0x8000_0000 + (1000 * 60 * 60 * 180) + 1, false),
                   None);
    }

    #[test]
    fn the_far_west() {
        assert_eq!(Position::from_u32(0x8000_0000 - (1000 * 60 * 60 * 180), false).unwrap().to_string(),
                   String::from("180°0′0″ W"));
    }

    #[test]
    fn the_far_west_minus_one() {
        assert_eq!(Position::from_u32(0x8000_0000 - (1000 * 60 * 60 * 180) - 1, false),
                   None);
    }
}


#[cfg(test)]
mod altitude_test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn base_level() {
        assert_eq!(Altitude::from_u32(10000000).to_string(),
                   String::from("0m"));
    }

    #[test]
    fn up_high() {
        assert_eq!(Altitude::from_u32(20000000).to_string(),
                   String::from("100000m"));
    }

    #[test]
    fn down_low() {
        assert_eq!(Altitude::from_u32(0).to_string(),
                   String::from("-100000m"));
    }

    #[test]
    fn with_decimal() {
        assert_eq!(Altitude::from_u32(50505050).to_string(),
                   String::from("405050.50m"));
    }
}
