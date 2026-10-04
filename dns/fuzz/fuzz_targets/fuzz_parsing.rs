#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Whatever the input, parsing must return rather than panic; whether it
    // succeeds is not the point.
    let _outcome = dns::Response::from_bytes(data);
});
