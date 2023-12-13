<div align="center">
<h1>dog</h1>

[dog](https://dns.lookup.dog/) is a command-line DNS client.

<a href="https://travis-ci.org/github/ogham/dog">
    <img src="https://travis-ci.org/ogham/dog.svg?branch=master" alt="Build status" />
</a>

<a href="https://saythanks.io/to/ogham%40bsago.me">
    <img src="https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg" alt="Say thanks!" />
</a>
</div>

![A screenshot of dog making a DNS request](dog-screenshot.png)

---

Dogs _can_ look up!

**dog** is a command-line DNS client, like `dig`.
It has colourful output, understands normal command-line argument syntax, supports the DNS-over-TLS and DNS-over-HTTPS protocols, and can emit JSON.

## Examples

    dog example.net                          Query a domain using default settings
    dog example.net MX                       ...looking up MX records instead
    dog example.net MX @1.1.1.1              ...using a specific nameserver instead
    dog example.net MX @1.1.1.1 -T           ...using TCP rather than UDP
    dog -q example.net -t MX -n 1.1.1.1 -T   As above, but using explicit arguments

---

## Command-line options

### Query options

    <arguments>              Human-readable host names, nameservers, types, or classes
    -q, --query=HOST         Host name or domain name to query
    -t, --type=TYPE          Type of the DNS record being queried (A, MX, NS...)
    -n, --nameserver=ADDR    Address of the nameserver to send packets to
    --class=CLASS            Network class of the DNS record being queried (IN, CH, HS)

### Sending options

    --edns=SETTING           Whether to OPT in to EDNS (disable, hide, show)
    --txid=NUMBER            Set the transaction ID to a specific value
    -Z=TWEAKS                Set uncommon protocol-level tweaks

### Protocol options

    -U, --udp                Use the DNS protocol over UDP
    -T, --tcp                Use the DNS protocol over TCP
    -S, --tls                Use the DNS-over-TLS protocol
    -H, --https              Use the DNS-over-HTTPS protocol

### Output options

    -1, --short              Short mode: display nothing but the first result
    -J, --json               Display the output as JSON
    --color, --colour=WHEN   When to colourise the output (always, automatic, never)
    --seconds                Do not format durations, display them as seconds
    --time                   Print how long the response took to arrive


---

## Installation

To install dog, you can download a pre-compiled binary, or you can compile it from source. You _may_ be able to install dog using your OS’s package manager, depending on your platform.


### Packages

- For Arch Linux, install the [`dog`](https://www.archlinux.org/packages/community/x86_64/dog/) package.
- For Homebrew on macOS, install the [`dog`](https://formulae.brew.sh/formula/dog) formula.
- For NixOS, install the [`dogdns`](https://search.nixos.org/packages?channel=unstable&show=dogdns&query=dogdns) package.


### Downloads

Binary downloads of dog are available from [the releases section on GitHub](https://github.com/ogham/dog/releases/) for 64-bit Windows, macOS, and Linux targets. They contain the compiled executable, the manual page, and shell completions.


### Compilation

dog is written in [Rust](https://www.rust-lang.org).
You will need rustc version [1.45.0](https://blog.rust-lang.org/2020/07/16/Rust-1.45.0.html) or higher.
The recommended way to install Rust for development is from the [official download page](https://www.rust-lang.org/tools/install), using rustup.

To build, download the source code and run:

    $ cargo build
    $ cargo test

- The [just](https://github.com/casey/just) command runner can be used to run some helpful development commands, in a manner similar to `make`.
Run `just --list` to get an overview of what’s available.

- If you are compiling a copy for yourself, be sure to run `cargo build --release` or `just build-release` to benefit from release-mode optimisations.
Copy the resulting binary, which will be in the `target/release` directory, into a folder in your `$PATH`.
`/usr/local/bin` is usually a good choice.

- To compile and install the manual pages, you will need [pandoc](https://pandoc.org/).
The `just man` command will compile the Markdown into manual pages, which it will place in the `target/man` directory.
To use them, copy them into a directory that `man` will read.
`/usr/local/share/man` is usually a good choice.

- To replace `nativetls` by `rustls`:

    $ cargo build --no-default-features --features with_tls,with_https,with_rustls

### Build for Alpine

    $ docker run --rm  -v "$PWD":/usr/src/myapp -w /usr/src/myapp instrumentisto/rust:1-alpine sh -c "apk add pkgconfig musl-dev openssl-dev git ; cargo build --release"


### Build for Buster

    $ docker run --rm --user "$(id -u)":"$(id -g)" -v "$PWD":/usr/src/myapp -w /usr/src/myapp instrumentisto/rust:1-buster cargo build --release

### Container image

To build the container image of dog, you can use Docker or Kaniko. Here an example using Docker:

    $ docker build -t dog .

You can then run it using the following command:

    $ docker run -it --rm dog

To run dog directly, you can then define the following alias:

    $ alias dog="docker run -it --rm dog"


### End-to-end testing

dog has an integration test suite written as [Specsheet](https://specsheet.software/) check documents.
If you have a copy installed, you can run:

    $ just xtests

Specsheet will test the compiled binary by making DNS requests over the network, checking that dog returns the correct results and does not crash.
Note that this will expose your IP address.
For more information, read [the xtests README](xtests/README.md).


### Feature toggles

dog has three Cargo features that can be switched off to remove functionality.
While doing so makes dog less useful, it results in a smaller binary that takes less time to build.

There are three feature toggles available, all of which are active by default:

- `with_idna`, which enables [IDNA](https://en.wikipedia.org/wiki/Internationalized_domain_name) processing
- `with_tls`, which enables DNS-over-TLS
- `with_https`, which enables DNS-over-HTTPS (requires `with_tls`)

Use `cargo` to build a binary that uses feature toggles. For example, to disable TLS and HTTPS support but keep IDNA support enabled, you can run:

    $ cargo build --no-default-features --features=with_idna

The list of features that have been disabled can be checked at runtime as part of the `--version` string.

### Debugging with traces

    $ DOG_DEBUG=trace dog --time -U -n 1.1.1.1 google.com

---

## Documentation

For documentation on how to use dog, see the website: <https://dns.lookup.dog/>


## See also

`mutt`, `tail`, `sleep`, `roff`


## Licence

dog’s source code is licenced under the [European Union Public Licence](https://choosealicense.com/licenses/eupl-1.2/).
