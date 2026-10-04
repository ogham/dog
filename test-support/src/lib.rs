//! Test-only support code shared by dog’s crates.
//!
//! - [`fixtures`] loads the responses captured from real servers by
//!   `tests/capture/capture.py`.
//! - [`wire`] walks and mutates raw DNS and HTTP messages, for the
//!   malformed-input cases that no real server will produce on demand.
//! - [`mock`] runs loopback UDP, TCP and HTTP servers that replay fixtures
//!   and record what they were sent.
//! - [`golden`] compares command output against checked-in golden files.
//! - [`watchdog`] turns a would-be infinite loop into a test failure.
//!
//! Everything here works on raw bytes and deliberately does not depend on
//! the `dns` crate, so tests never check dog’s parser against itself.

pub mod fixtures;
pub mod golden;
pub mod mock;
#[cfg(feature = "tls")]
pub mod tls;
pub mod watchdog;
pub mod wire;
