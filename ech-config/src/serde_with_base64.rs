//! De/Serialization of hexadecimal encoded bytes
//!
//! This modules is only available when using the `hex` feature of the crate.

use serde_with::de::DeserializeAs;
use serde_with::ser::SerializeAs;
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serializer};
use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::marker::PhantomData;

/// Serialize bytes as a base64 string
///
/// The type serializes a sequence of bytes as a base64 string.
/// It works on any type implementing `AsRef<[u8]>` for serialization and `From<Vec<u8>>` for deserialization.
///
/// # Example
///
/// ```rust
/// # #[cfg(feature = "macros")] {
/// # use serde_derive::{Deserialize, Serialize};
/// # use serde_json::json;
/// # use serde_with::serde_as;
/// #
/// #[serde_as]
/// # #[derive(Debug, PartialEq, Eq)]
/// #[derive(Deserialize, Serialize)]
/// struct BytesLowercase(
///     // Equivalent to serde_with_base64::Base64
///     #[serde_as(as = "serde_with_base64::Base64")]
///     Vec<u8>
/// );
///
/// #[serde_as]
/// # #[derive(Debug, PartialEq, Eq)]
/// #[derive(Deserialize, Serialize)]
/// struct BytesUppercase(
///     #[serde_as(as = "serde_with_base64::Base64")]
///     Vec<u8>
/// );
///
/// let b = b"Hello World!";
///
/// // Base64 with lowercase letters
/// assert_eq!(
///     json!("48656c6c6f20576f726c6421"),
///     serde_json::to_value(BytesLowercase(b.to_vec())).unwrap()
/// );
/// // Base64 with uppercase letters
/// assert_eq!(
///     json!("48656C6C6F20576F726C6421"),
///     serde_json::to_value(BytesUppercase(b.to_vec())).unwrap()
/// );
///
/// // Serialization always work from lower- and uppercase characters, even mixed case.
/// assert_eq!(
///     BytesLowercase(vec![0x00, 0xaa, 0xbc, 0x99, 0xff]),
///     serde_json::from_value(json!("00aAbc99FF")).unwrap()
/// );
/// assert_eq!(
///     BytesUppercase(vec![0x00, 0xaa, 0xbc, 0x99, 0xff]),
///     serde_json::from_value(json!("00aAbc99FF")).unwrap()
/// );
///
/// /////////////////////////////////////
/// // Arrays are supported in Rust 1.48+
///
/// # #[rustversion::since(1.48)]
/// # fn test_array() {
/// #[serde_as]
/// # #[derive(Debug, PartialEq, Eq)]
/// #[derive(Deserialize, Serialize)]
/// struct ByteArray(
///     #[serde_as(as = "serde_with_base64::Base64")]
///     [u8; 12]
/// );
///
/// let b = b"Hello World!";
///
/// assert_eq!(
///     json!("48656c6c6f20576f726c6421"),
///     serde_json::to_value(ByteArray(b.clone())).unwrap()
/// );
///
/// // Serialization always work from lower- and uppercase characters, even mixed case.
/// assert_eq!(
///     ByteArray([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xaa, 0xbc, 0x99, 0xff]),
///     serde_json::from_value(json!("0011223344556677aAbc99FF")).unwrap()
/// );
///
/// // Remember that the conversion may fail. (The following errors are specific to fixed-size arrays)
/// let error_result: Result<ByteArray, _> = serde_json::from_value(json!("42")); // Too short
/// error_result.unwrap_err();
///
/// let error_result: Result<ByteArray, _> =
///     serde_json::from_value(json!("000000000000000000000000000000")); // Too long
/// error_result.unwrap_err();
/// # };
/// # #[rustversion::before(1.48)]
/// # fn test_array() {}
/// # test_array();
/// # }
/// ```
#[derive(Copy, Clone, Debug, Default)]
pub struct Base64(PhantomData<()>);

impl<T> SerializeAs<T> for Base64
where
    T: AsRef<[u8]>,
{
    fn serialize_as<S>(source: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(source))
    }
}

impl<'de, T> DeserializeAs<'de, T> for Base64
where
    T: TryFrom<Vec<u8>>,
{
    fn deserialize_as<D>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
    {
        <Cow<'de, str> as Deserialize<'de>>::deserialize(deserializer)
            .and_then(|s| base64::decode(&*s).map_err(Error::custom))
            .and_then(|vec: Vec<u8>| {
                let length = vec.len();
                vec.try_into().map_err(|_e: T::Error| {
                    Error::custom(format!(
                        "Can't convert a Byte Vector of length {} to the output type.",
                        length
                    ))
                })
            })
    }
}

