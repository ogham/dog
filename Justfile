all: build test xtests
all-release: build-release test-release xtests-release
all-quick: build-quick test-quick xtests-quick

export DOG_DEBUG := ""

# the lizard complexity checker; set LIZARD if it lives in a virtualenv
lizard := env_var_or_default("LIZARD", "lizard")

# files that are not dog’s own code: test code, and the build script
# (whose logic lives in build-support/, which is measured)
coverage-ignore := '(^|/)(build\.rs|test-support/|tests/)'


#----------#
# building #
#----------#

# compile the dog binary
@build:
    cargo build

# compile the dog binary (in release mode)
@build-release:
    cargo build --release --verbose
    strip "${CARGO_TARGET_DIR:-target}/release/dog"

# produce an HTML chart of compilation timings
@build-time:
    cargo +nightly clean
    cargo +nightly build -Z timings

# compile the dog binary (without some features)
@build-quick:
    cargo build --no-default-features

# check that everything can compile, tests included
@check:
    cargo check --workspace --all-targets

# check that the Windows-only code still compiles
@check-windows:
    cargo check --workspace --all-targets --target x86_64-pc-windows-gnu


#---------------#
# running tests #
#---------------#

# run the unit, integration and end-to-end tests, with and without the optional features
@test:
    cargo test --workspace -- --quiet
    cargo test --workspace --no-default-features -- --quiet

# run the tests (in release mode)
@test-release:
    cargo test --workspace --release --verbose

# run the tests (without some features)
@test-quick:
    cargo test --workspace --no-default-features -- --quiet

# run the tests that talk to real servers on the internet
@test-live:
    cargo test --workspace -- --ignored

# rewrite the golden output files from the current behaviour, then review the diff
@bless:
    DOG_BLESS=1 cargo test --workspace -- --quiet
    DOG_BLESS=1 cargo test --workspace --no-default-features -- --quiet


#----------#
# fixtures #
#----------#

# capture DNS and DNS-over-HTTPS responses from real servers into tests/fixtures
@capture-fixtures *args:
    python3 tests/capture/capture.py {{args}}

# regenerate the throwaway TLS certificates the tests trust
@gen-test-certs:
    sh tests/fixtures/tls/make-certs.sh


#------------------------#
# running extended tests #
#------------------------#

# run extended tests
@xtests *args:
    specsheet xtests/{options,live,madns}/*.toml -shide {{args}} \
        -O cmd.target.dog="${CARGO_TARGET_DIR:-../../target}/debug/dog"

# run extended tests (in release mode)
@xtests-release *args:
    specsheet xtests/{options,live,madns}/*.toml {{args}} \
        -O cmd.target.dog="${CARGO_TARGET_DIR:-../../target}/release/dog"

# run extended tests (omitting certain feature tests)
@xtests-quick *args:
    specsheet xtests/options/*.toml xtests/live/{basics,tcp}.toml -shide {{args}} \
        -O cmd.target.dog="${CARGO_TARGET_DIR:-../../target}/debug/dog"

# run extended tests against a local madns instance
@xtests-madns-local *args:
    env MADNS_ARGS="@localhost:5301 --tcp" \
        specsheet xtests/madns/*.toml -shide {{args}} \
            -O cmd.target.dog="${CARGO_TARGET_DIR:-../../target}/debug/dog"

# display the number of extended tests that get run
@count-xtests:
    grep -F '[[cmd]]' -R xtests | wc -l

# builds dog and runs extended tests with features disabled
@feature-checks *args:
    cargo build --no-default-features
    specsheet xtests/features/none.toml -shide {{args}} \
        -O cmd.target.dog="${CARGO_TARGET_DIR:-../../target}/debug/dog"


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

# lint the code, with and without the optional features
@clippy:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo clippy --workspace --all-targets --no-default-features -- -D warnings

# fail if any function’s cyclomatic complexity is over 10, tests included
@complexity:
    command -v {{lizard}} >/dev/null || (echo "lizard not found: python3 -m venv ~/.venvs/lizard && ~/.venvs/lizard/bin/pip install lizard, then set LIZARD=~/.venvs/lizard/bin/lizard" && exit 1)
    {{lizard}} -l rust -l python -C 10 -w -x './target/*' -x './dns/fuzz/target/*' .

# measure test coverage of both feature sets together; fail under 99% of lines
@coverage:
    command -v cargo-llvm-cov >/dev/null || (echo "cargo-llvm-cov not installed: rustup component add llvm-tools-preview && cargo install cargo-llvm-cov" && exit 1)
    cargo llvm-cov clean --workspace
    cargo llvm-cov --no-report --workspace
    cargo llvm-cov --no-report --workspace --no-default-features
    cargo llvm-cov report --workspace --html --output-dir target/coverage --ignore-filename-regex '{{coverage-ignore}}'
    cargo llvm-cov report --workspace --summary-only --fail-under-lines 99 --ignore-filename-regex '{{coverage-ignore}}'

# run every check: tests, lints, complexity, coverage, and the Windows build
verify: test clippy complexity coverage check-windows

# update dependency versions, and check for outdated ones
@update-deps:
    cargo update
    command -v cargo-outdated >/dev/null || (echo "cargo-outdated not installed" && exit 1)
    cargo outdated

# list unused dependencies
@unused-deps:
    command -v cargo-udeps >/dev/null || (echo "cargo-udeps not installed" && exit 1)
    cargo +nightly udeps

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
    pandoc --standalone -f markdown -t man man/dog.1.md > "${CARGO_TARGET_DIR:-target}/man/dog.1"

# build and preview the man page
@man-preview: man
    man "${CARGO_TARGET_DIR:-target}/man/dog.1"


#-----------#
# packaging #
#-----------#

# create a distributable package
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
