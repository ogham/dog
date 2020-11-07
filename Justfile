all: build test xtests
all-release: build-release test-release xtests-release
all-quick: build-quick test-quick xtests-quick

export DOG_DEBUG := ""


# compiles the dog binary
@build:
    cargo build

# compiles the dog binary (in release mode)
@build-release:
    cargo build --release --verbose
    strip "${CARGO_TARGET_DIR:-target}/release/dog"

# compiles the dog binary (without some features)
@build-quick:
    cargo build --no-default-features


# runs unit tests
@test:
    cargo test --workspace -- --quiet

# runs unit tests (in release mode)
@test-release:
    cargo test --release --workspace --verbose

# runs unit tests (without some features)
@test-quick:
    cargo test --workspace --no-default-features -- --quiet

# runs mutation tests
@test-mutation:
    cargo +nightly test    --package dns --features=dns/with_mutagen -- --quiet
    cargo +nightly mutagen --package dns --features=dns/with_mutagen


# runs extended tests
@xtests:
    specsheet xtests/*.toml -O cmd.target.dog="${CARGO_TARGET_DIR:-../target}/debug/dog"

# runs extended tests (in release mode)
@xtests-release:
    specsheet xtests/*.toml -O cmd.target.dog="${CARGO_TARGET_DIR:-../target}/release/dog"

# runs extended tests (omitting certain feature tests)
@xtests-quick:
    specsheet xtests/*.toml -O cmd.target.dog="${CARGO_TARGET_DIR:-../target}/debug/dog" --skip-tags=udp,tls,https,json


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

# updates dependency versions, and checks for outdated ones
@update-deps:
    cargo update
    command -v cargo-outdated >/dev/null || (echo "cargo-outdated not installed" && exit 1)
    cargo outdated

# lists unused dependencies
@unused-deps:
    command -v cargo-udeps >/dev/null || (echo "cargo-udeps not installed" && exit 1)
    cargo +nightly udeps

# prints versions of the necessary build tools
@versions:
    rustc --version
    cargo --version


# renders the documentation
@doc:
    cargo doc --no-deps --workspace

# builds the man pages
@man:
    mkdir -p "${CARGO_TARGET_DIR:-target}/man"
    pandoc --standalone -f markdown -t man man/dog.1.md > "${CARGO_TARGET_DIR:-target}/man/dog.1"

# builds and previews the man page
@man-preview: man
    man "${CARGO_TARGET_DIR:-target}/man/dog.1"


# creates a distributable package
zip desc exe="dog":
    #!/usr/bin/env perl
    use Archive::Zip;
    -e 'target/release/{{ exe }}' || die 'Binary not built!';
    -e 'target/man/dog.1' || die 'Man page not built!';
    my $zip = Archive::Zip->new();
    $zip->addFile('completions/dog.bash');
    $zip->addFile('completions/dog.zsh');
    $zip->addFile('completions/dog.fish');
    $zip->addFile('target/man/dog.1', 'man/dog.1');
    $zip->addFile('target/release/{{ exe }}', 'bin/{{ exe }}');
    $zip->writeToFileNamed('dog-{{ desc }}.zip') == AZ_OK || die 'Zip write error!';
    system 'unzip -l "dog-{{ desc }}".zip'
