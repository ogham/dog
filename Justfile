all: build test xtests
all-release: build-release test-release xtests-release

export DOG_DEBUG := ""


# compiles the dog binary
@build:
    cargo build

# compiles the dog binary (in release mode)
@build-release:
    cargo build --release --verbose
    strip target/release/dog

# runs unit tests
@test:
    cargo test --all -- --quiet

# runs unit tests (in release mode)
@test-release:
    cargo test --release --all --verbose

# runs extended tests
@xtests:
    specsheet xtests/*.toml -O cmd.target.dog="${CARGO_TARGET_DIR:-../target}/debug/dog"

# runs extended tests (in release mode)
@xtests-release:
    specsheet xtests/*.toml -O cmd.target.dog="${CARGO_TARGET_DIR:-../target}/release/dog"

# renders the documentation
@doc args="":
    cargo doc --no-deps --all {{args}}

# runs fuzzing on the dns crate
@fuzz:
    cargo +nightly fuzz --version
    cd dns; cargo +nightly fuzz run fuzz_parsing -- -jobs=`nproc` -workers=`nproc` -runs=69105

# prints out the data that caused crashes during fuzzing as hexadecimal
@fuzz-hex:
	for crash in dns/fuzz/artifacts/fuzz_parsing/crash-*; do echo; echo $crash; hexyl $crash; done

# removes fuzz log files
@fuzz-clean:
	rm dns/fuzz/fuzz-*.log

# lints the code
@clippy:
    touch dns/src/lib.rs
    cargo clippy

# generates a code coverage report using tarpaulin via docker
@coverage-docker:
    docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin cargo tarpaulin --all --out Html

# updates versions, and checks for outdated ones
@update:
    cargo update; cargo outdated
    cd dns/fuzz; cargo update; cargo outdated


# builds the man pages
@man:
    mkdir -p "${CARGO_TARGET_DIR:-target}/man"
    pandoc --standalone -f markdown -t man man/dog.1.md > "${CARGO_TARGET_DIR:-target}/man/dog.1"

# builds and previews the man page
@man-preview: man
    man "${CARGO_TARGET_DIR:-target}/man/dog.1"
