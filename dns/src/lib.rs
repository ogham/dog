#![warn(deprecated_in_future)]
#![warn(future_incompatible)]
#![warn(missing_copy_implementations)]
#![warn(missing_docs)]
#![warn(nonstandard_style)]
#![warn(rust_2018_compatibility)]
#![warn(rust_2018_idioms)]
#![warn(single_use_lifetimes)]
#![warn(trivial_casts, trivial_numeric_casts)]
#![warn(unused)]

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::wildcard_imports)]

#![deny(unsafe_code)]


//! The DNS crate is the ‘library’ part of dog. It implements the DNS
//! protocol: creating and decoding packets from their byte structure.


mod types;
pub use self::types::*;

mod strings;

mod wire;
pub use self::wire::{Wire, WireError, find_qtype_number};

pub mod record;
