#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate dns;
use dns::Response;

fuzz_target!(|data: &[u8]| {
    let _ = Response::from_bytes(data);
});
