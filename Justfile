all: build test xtests
all-release: build-release test-release xtests-release
all-quick: build-quick test-quick xtests-quick

export DOGE_DEBUG := ""


#----------#
# building #
#----------#

# compile the doge binary
@build:
    cargo build

# compile the doge binary (in release mode)
@build-release:
    cargo build --release --verbose
    strip "${CARGO_TARGET_DIR:-target}/release/doge"

# produce an HTML chart of compilation timings
@build-time:
    cargo +nightly clean
    cargo +nightly build -Z timings

# compile the doge binary (without some features)
@build-quick:
    cargo build --no-default-features

# check that the doge binary can compile
@check:
    cargo check


#---------------#
# running tests #
#---------------#

# run unit tests
@test:
    cargo test --workspace -- --quiet

# run unit tests (in release mode)
@test-release:
    cargo test --workspace --release --verbose

# run unit tests (without some features)
@test-quick:
    cargo test --workspace --no-default-features -- --quiet

# run mutation tests
@test-mutation:
    cargo +nightly test    --package dns --features=dns/with_mutagen -- --quiet
    cargo +nightly mutagen --package dns --features=dns/with_mutagen


#------------------------#
# running extended tests #
#------------------------#

# run extended tests
@xtests *args:
    specsheet xtests/{options,live,madns}/*.toml -shide {{args}} \
        -O cmd.target.doge="${CARGO_TARGET_DIR:-../../target}/debug/doge"

# run extended tests (in release mode)
@xtests-release *args:
    specsheet xtests/{options,live,madns}/*.toml {{args}} \
        -O cmd.target.doge="${CARGO_TARGET_DIR:-../../target}/release/doge"

# run extended tests (omitting certain feature tests)
@xtests-quick *args:
    specsheet xtests/options/*.toml xtests/live/{basics,tcp}.toml -shide {{args}} \
        -O cmd.target.doge="${CARGO_TARGET_DIR:-../../target}/debug/doge"

# run extended tests against a local madns instance
@xtests-madns-local *args:
    env MADNS_ARGS="@localhost:5301 --tcp" \
        specsheet xtests/madns/*.toml -shide {{args}} \
            -O cmd.target.doge="${CARGO_TARGET_DIR:-../../target}/debug/doge"

# display the number of extended tests that get run
@count-xtests:
    grep -F '[[cmd]]' -R xtests | wc -l


#---------#
# fuzzing #
#---------#

# run fuzzing on the dns crate
@fuzz:
    cargo +nightly fuzz --version
    cd dns; cargo +nightly fuzz run fuzz_parsing -- -jobs=`nproc` -workers=`nproc` -runs=69105

# print out the data that caused crashes during fuzzing as hexadecimal
@fuzz-hex:
    for crash in dns/fuzz/artifacts/fuzz_parsing/crash-*; do echo; echo $crash; hexyl $crash; done

# remove fuzz log files
@fuzz-clean:
    rm dns/fuzz/fuzz-*.log


#-----------------------#
# code quality and misc #
#-----------------------#

# lint the code
@clippy:
    touch dns/src/lib.rs
    cargo clippy

# generate a code coverage report using tarpaulin via docker
@coverage-docker:
    docker run --security-opt seccomp=unconfined -v "${PWD}:/volume" xd009642/tarpaulin cargo tarpaulin --all --out Html

# update dependency versions, and check for outdated ones
@update-deps:
    cargo update
    command -v cargo-outdated >/dev/null || (echo "cargo-outdated not installed" && exit 1)
    cargo outdated

# list unused dependencies
@unused-deps:
    command -v cargo-udeps >/dev/null || (echo "cargo-udeps not installed" && exit 1)
    cargo +nightly udeps

# builds doge and runs extended tests with features disabled
@feature-checks *args:
    cargo build --no-default-features
    specsheet xtests/features/none.toml -shide {{args}} \
        -O cmd.target.doge="${CARGO_TARGET_DIR:-../../target}/debug/doge"

# print versions of the necessary build tools
@versions:
    rustc --version
    cargo --version


#---------------#
# documentation #
#---------------#

# render the documentation
@doc:
    cargo doc --no-deps --workspace

# build the man pages
@man:
    mkdir -p "${CARGO_TARGET_DIR:-target}/man"
    pandoc --standalone -f markdown -t man man/doge.1.md > "${CARGO_TARGET_DIR:-target}/man/doge.1"

# build and preview the man page
@man-preview: man
    man "${CARGO_TARGET_DIR:-target}/man/doge.1"


#-----------#
# packaging #
#-----------#

# create a distributable package
zip desc exe="doge":
    #!/usr/bin/env perl
    use Archive::Zip;
    -e 'target/release/{{ exe }}' || die 'Binary not built!';
    -e 'target/man/doge.1' || die 'Man page not built!';
    my $zip = Archive::Zip->new();
    $zip->addFile('completions/doge.bash');
    $zip->addFile('completions/doge.zsh');
    $zip->addFile('completions/doge.fish');
    $zip->addFile('target/man/doge.1', 'man/doge.1');
    $zip->addFile('target/release/{{ exe }}', 'bin/{{ exe }}');
    $zip->writeToFileNamed('doge-{{ desc }}.zip') == AZ_OK || die 'Zip write error!';
    system 'unzip -l "doge-{{ desc }}".zip'
