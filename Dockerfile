# Builds dog against the system OpenSSL in the Rust image, and runs it on
# the current Debian stable, which ships a matching libssl.

FROM rust AS build

WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs /build/
COPY build-support /build/build-support
COPY src /build/src
COPY dns /build/dns
COPY dns-transport /build/dns-transport
COPY test-support /build/test-support

RUN cargo build --release --locked

FROM debian:stable-slim

# ca-certificates depends on openssl, which brings in libssl under whatever
# name the current release gives it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /build/target/release/dog /dog

ENTRYPOINT ["/dog"]
