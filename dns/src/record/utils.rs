use std::fmt;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::ops::RangeInclusive;

use crate::wire::*;

/// A kinda hacky but alright way to avoid copying tons of data
pub(crate) trait CursorExt {
    /// Replace this when #[feature(cursor_remaining)] is stabilised
    fn std_remaining_slice(&self) -> &[u8];

    /// Convenience
    fn truncated(&self, length: u64) -> Self;
    fn with_truncated<T>(&mut self, length: u64, f: impl FnOnce(&mut Self, usize) -> T) -> T;
}

impl CursorExt for Cursor<&[u8]> {
    fn std_remaining_slice(&self) -> &[u8] {
        let inner = self.get_ref();
        let len = self.position().min(inner.as_ref().len() as u64);
        &inner[(len as usize)..]
    }
    fn truncated(&self, to_length: u64) -> Self {
        let inner = self.get_ref();
        let len = inner.len() as u64;
        let start = self.position().min(len);
        let end = (start + to_length).min(len);
        let trunc = &inner[(start as usize)..(end as usize)];
        Cursor::new(trunc)
    }
    fn with_truncated<T>(&mut self, length: u64, f: impl FnOnce(&mut Self, usize) -> T) -> T {
        let mut trunc = self.truncated(length);
        let len_hint = trunc.get_ref().len();
        let ret = f(&mut trunc, len_hint);
        self.seek(SeekFrom::Current(trunc.position() as i64))
            .unwrap();
        ret
    }
}

/// Read a bunch of specific endian integers and convert them to an enum, for example
pub(crate) fn read_convert<Raw: Sized, Nice: From<Raw>>(
    cursor: &mut Cursor<&[u8]>,
    len: usize,
    mut f: impl FnMut(&mut Cursor<&[u8]>) -> io::Result<Raw>,
) -> Result<Vec<Nice>, WireError> {
    let size = core::mem::size_of::<Raw>();
    if len % size != 0 {
        return Err(WireError::IO);
    }
    let mut collector = Vec::with_capacity(len / size);
    let reader = core::iter::from_fn(|| f(cursor).ok().map(Nice::from));
    collector.extend(reader);
    Ok(collector)
}

/// An opaque piece of data, displayed as base64
///
/// e.g. [crate::record::svcb::SvcParams::ech]
#[derive(Debug, Clone, PartialEq)]
pub struct Opaque(pub Vec<u8>);

impl From<Vec<u8>> for Opaque {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl fmt::Display for Opaque {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        base64::display::Base64Display::with_config(&self.0, base64::STANDARD).fmt(f)
    }
}

pub(crate) trait ReadFromCursor: Sized {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self>;
}

impl ReadFromCursor for Opaque {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        read_vec(cursor, 0..=u16::MAX).map(Self)
    }
}

fn read_vec_of_len(
    cursor: &mut Cursor<&[u8]>,
    limit: RangeInclusive<u16>,
    len: u16,
) -> io::Result<Vec<u8>> {
    if !limit.contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("invalid length {}: must be within {:?}", len, limit),
        ));
    }
    let mut vec = vec![0u8; usize::from(len)];
    cursor.read_exact(&mut vec[..])?;
    Ok(vec)
}

fn read_vec(cursor: &mut Cursor<&[u8]>, limit: RangeInclusive<u16>) -> io::Result<Vec<u8>> {
    let len = cursor.read_u16::<BigEndian>()?;
    log::trace!("read opaque length = {}", len);
    read_vec_of_len(cursor, limit, len)
}

impl Opaque {
    pub(crate) fn read_known_len(cursor: &mut Cursor<&[u8]>, len: u16) -> io::Result<Self> {
        let vec = read_vec_of_len(cursor, 0..=u16::MAX, len)?;
        Ok(Self(vec))
    }
}

macro_rules! u16_enum {
    {
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vattr:meta])*
                $variant:ident = $lit:literal,)+
        }
    } => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq)]
        #[repr(u16)]
        $vis enum $name {
            $(
                $(#[$vattr])*
                $variant = $lit,)+
        }
        impl core::convert::TryFrom<u16> for $name {
            type Error = std::io::Error;

            fn try_from(int: u16) -> Result<Self, Self::Error> {
                match int {
                    $($lit => Ok(Self::$variant),)+
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("invalid value for {}: {:04x}", stringify!($name), int)
                        )
                    )
                }
            }
        }
    };
    {
        $(#[$attr:meta])*
        $vis:vis enum $name:ident {
            $(
                $(#[$vattr:meta])*
                $variant:ident = $lit:literal,)+
            $(
                @unknown
                $(#[$uattr:meta])*
                $unknown:ident (u16),
                $(
                    $(#[$vattr2:meta])*
                    $variant2:ident = $lit2:literal,)*
            )?
        }
    } => {
        $(#[$attr])*
        #[derive(Debug, Clone, PartialEq)]
        #[repr(u16)]
        $vis enum $name {
            $(
                $(#[$vattr])*
                $variant = $lit,)+
            $(
                $(#[$uattr])*
                $unknown(u16),
                $(
                    $(#[$vattr2])*
                    $variant2 = $lit2,)*
            )?
        }
        impl From<u16> for $name {
            fn from(int: u16) -> Self {
                match int {
                    $($lit => Self::$variant,)+
                    $(
                        $($lit2 => Self::$variant2,)*
                        _ => Self::$unknown(int),
                    )?
                }
            }
        }
    };
}

