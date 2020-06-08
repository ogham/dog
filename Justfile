all: build test
all-release: build-release test-release

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

# updates versions, and checks for outdated ones
@update:
    cargo update; cargo outdated
    cd dns/fuzz; cargo update; cargo outdated
