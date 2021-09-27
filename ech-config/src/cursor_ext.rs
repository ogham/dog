use byteorder::{BigEndian, ReadBytesExt};
use serde::{Serialize, Deserialize};
use std::convert::TryFrom;
use std::fmt;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::ops::RangeInclusive;

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

pub(crate) trait ReadFromCursor: Sized {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self>;
}

impl<const MIN: u16, const MAX: u16> TryFrom<Vec<u8>> for Opaque<MIN, MAX> {
    type Error = usize;
    fn try_from(vec: Vec<u8>) -> Result<Self, Self::Error> {
        if !(MIN as usize..=MAX as usize).contains(&vec.len()) {
            Err(vec.len())
        } else {
            Ok(Self(vec))
        }
    }
}

#[serde_with::serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Opaque<const MIN: u16, const MAX: u16>(
    #[serde_as(as = "crate::serde_with_base64::Base64")] pub Vec<u8>,
);

impl<const MIN: u16, const MAX: u16> Opaque<MIN, MAX> {
    pub(crate) fn read_known_len(cursor: &mut Cursor<&[u8]>, len: u16) -> io::Result<Self> {
        let vec = read_vec_of_len(cursor, MIN..=MAX, len)?;
        Ok(Self(vec))
    }
}

pub fn read_vec_of_len(
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

pub fn read_vec(cursor: &mut Cursor<&[u8]>, limit: RangeInclusive<u16>) -> io::Result<Vec<u8>> {
    let len = cursor.read_u16::<BigEndian>()?;
    log::trace!("read opaque length = {}", len);
    read_vec_of_len(cursor, limit, len)
}

impl<const MIN: u16, const MAX: u16> ReadFromCursor for Opaque<MIN, MAX> {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let vec = read_vec(cursor, MIN..=MAX)?;
        Ok(Opaque(vec))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Ascii(pub Vec<u8>);

impl From<Vec<u8>> for Ascii {
    fn from(vec: Vec<u8>) -> Self {
        Self(vec)
    }
}

impl fmt::Display for Ascii {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0
            .iter()
            .copied()
            .map(std::ascii::escape_default)
            .try_for_each(|esc| esc.fmt(f))
    }
}

impl ReadFromCursor for Ascii {
    fn read_from(cursor: &mut Cursor<&[u8]>) -> io::Result<Self> {
        let vec = read_vec(cursor, 0..=u16::MAX)?;
        Ok(Ascii(vec))
    }
}
