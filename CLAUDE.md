# Dog - DNS client

A command-line DNS client (like dig, but more user-friendly).

## Build

Needs Rust 1.87 or newer (rustup stable) and, on Debian/Ubuntu, `build-essential pkg-config libssl-dev`.
TLS goes through the system OpenSSL, linked dynamically; there is no vendored or static TLS build.

```
cargo build --release
```

## Project structure

- `dns/` - DNS protocol library (record types, wire format parsing)
- `dns-transport/` - DNS transport layer (UDP, TCP, TLS, HTTPS)
- `src/` - CLI binary (argument parsing, output formatting)
- `build-support/version.rs` - pure functions behind `build.rs` (version and help text)
- `test-support/` - test-only crate: fixture loading, DNS/HTTP wire mutation helpers, loopback mock UDP/TCP/HTTP/TLS servers
- `tests/e2e/` - end-to-end tests running the real binary against the mock servers
- `tests/fixtures/` - responses captured from real servers by `tests/capture/capture.py` (public resolvers, plus a local BIND container for record types no public server has)
- `tests/golden/` - golden output files

## Testing

```
cargo test --workspace
cargo test --workspace --no-default-features
```

- Tests never use the internet. Live tests are `#[ignore]`d and run with `just test-live`.
- Fixtures must come from real servers (`just capture-fixtures`). Hand-made bytes are only for malformed or hostile input, and are made by mutating a real fixture with `test_support::wire`.
- After a deliberate output change, `just bless` rewrites the golden files; review the diff.
- `just coverage` (cargo-llvm-cov, both feature sets merged, fails under 99% of lines) and `just complexity` (lizard, fails over CCN 10) are the quality gates; `just verify` runs everything.
