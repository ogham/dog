% dog(1) v0.2.0-pre

<!-- This is the dog(1) man page, written in Markdown. -->
<!-- To generate the roff version, run `just man`, -->
<!-- and the man page will appear in the ‘target’ directory. -->


NAME
====

dog — a command-line DNS client


SYNOPSIS
========

`dog [options] [domains...]`

**dog** is a command-line DNS client.
It has colourful output, supports the DNS-over-TLS and DNS-over-HTTPS protocols, and can emit JSON.


EXAMPLES
========

`dog example.net`
: Query the `A` record of a domain using default settings

`dog example.net MX`
: ...looking up `MX` records instead

`dog example.net MX @1.1.1.1`
: ...using a specific nameserver instead

`dog example.net MX @1.1.1.1 -T`
: ...using TCP rather than UDP

`dog -q example.net -t MX -n 1.1.1.1 -T`
: As above, but using explicit arguments

`dog example.net --https @https://dns.quad9.net/dns-query`
: Query using DNS-over-HTTPS


QUERY OPTIONS
=============

`-q`, `--query=HOST`
: Host name or domain name to query.

`-t`, `--type=TYPE`
: Type of the DNS record being queried (`A`, `MX`, `NS`...). A type can also be given as its number, or in the generic form of RFC 3597, such as `TYPE65`.

`-n`, `--nameserver=ADDR`
: Address of the nameserver to send packets to.

`--class=CLASS`
: Network class of the DNS record being queried (`IN`, `CH`, `HS`). A class can also be given as its number, or in the generic form, such as `CLASS3`.

By default, dog will request A records using the system default resolver. At least one domain name must be passed — dog will not automatically query the root nameservers. To query the root, pass ‘`.`’ as the domain.

Query options passed in using a command-line option, such as ‘`--query lookup.dog`’ or ‘`--type MX`’, or as plain arguments, such as ‘`lookup.dog`’ or ‘`MX`’. dog will make an intelligent guess as to what plain arguments mean (`MX` is quite clearly a type), which makes it easier to compose ad-hoc queries quickly. If precision is desired, use the long-form options.

If more than one domain, type, nameserver, or class is specified, dog will perform one query for each combination, and display the combined results in a table. For example, passing three type arguments and two domain name arguments will send six requests.

dog refuses a domain that is empty, has an empty label (such as ‘`a..b`’), has a label that contains a space or a control character or is longer than 63 bytes, or is longer than 255 bytes in all. A final dot is allowed. With IDNA support, a name in Unicode is sent in its ASCII form, so ‘`bücher.example`’ is sent as ‘`xn--bcher-kva.example`’.

DNS traditionally uses port 53 for both TCP and UDP. To use a resolver with a different port, include the port number after a colon (`:`) in the nameserver address. An IPv6 address with a port goes in brackets, as in ‘`[2001:db8::53]:5353`’.


SENDING OPTIONS
===============

`--edns=SETTING`
: Whether to opt in to EDNS. This can be ‘`disable`’ (or ‘`off`’), ‘`hide`’, or ‘`show`’.

`--txid=NUMBER`
: Set the transaction ID to a specific value, in decimal, or in hexadecimal after ‘`0x`’.

`--timeout=SECONDS`
: How long to wait for each answer before giving up, in seconds; fractions are allowed, and the most is 3600. The default is 5. Each query dog sends gets this long, so a lookup of several record types can take several times as long in all. When dog asks a recursive resolver, set it above the time that resolver takes to give up, so dog reports the resolver’s answer (SERVFAIL, say) rather than its own timeout.

`-Z TWEAK`
: Set an uncommon protocol-level tweak. This can be given more than once; see PROTOCOL TWEAKS below.


TRANSPORT OPTIONS
=================

`-U`, `--udp`
: Use the DNS protocol over UDP.

`-T`, `--tcp`
: Use the DNS protocol over TCP.

`-S`, `--tls`
: Use the DNS-over-TLS protocol.

`-H`, `--https`
: Use the DNS-over-HTTPS protocol.

By default, dog will use the UDP protocol, automatically re-sending the request using TCP if the response indicates that the message is too large for UDP. Passing `--udp` will only use UDP, and dog will warn that a truncated response may be missing records; passing `--tcp` will use TCP by default.

The DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) protocols are available with the `--tls` and `--https` options. Bear in mind that the system default resolver is unlikely to respond to requests using these protocols. Servers’ certificates are checked by the system’s OpenSSL, against the certificates it trusts. DNS-over-HTTPS requests are sent over HTTP/2 or HTTP/1.1, whichever the server chooses.

Note that if a hostname or domain name is given as a nameserver, rather than an IP address, the resolution of that host is performed by the operating system, _not_ by dog.

Unlike the others, the HTTPS transport type requires an entire URL, complete with protocol, domain name, and path, such as ‘`https://cloudflare-dns.com/dns-query`’. The URL may have a port, but may not contain spaces, control characters, or a user name or password.

dog gives up on a nameserver that has not finished answering within five seconds. That time covers the whole exchange: looking up the nameserver’s address, connecting, sending the query, and receiving all of the answer, however slowly it arrives. Each query gets its own five seconds, as does each of the UDP and TCP attempts of the automatic transport.

Without a nameserver, dog uses the ones in `/etc/resolv.conf`, IPv4 and IPv6 alike, up to three of them, as the system’s own resolver does: if one does not answer, dog tries the next.


OUTPUT OPTIONS
==============

`-1`, `--short`
: Short mode: display nothing but the answers, one per line.

`-J`, `--json`
: Display the output as JSON.

`--color`, `--colour=WHEN`
: When to colourise the output. This can be ‘`always`’ (or ‘`yes`’), ‘`automatic`’ (or ‘`auto`’), or ‘`never`’ (or ‘`no`’), in any case. Automatically, dog uses colours only when it is writing to a terminal, `NO_COLOR` is not set, and `TERM` is not ‘`dumb`’.

`--seconds`
: Do not format durations as hours and minutes; instead, display them as seconds.

`--time`
: Print how long the response took to arrive.

Names are shown the way dig shows them: a byte that is not printable ASCII is written as a backslash and its three-digit decimal value, and a dot, backslash, or quote inside a label is written after a backslash. Text in a record is shown in quotes, with quotes and backslashes escaped, and any byte that is not printable ASCII written as a backslash and its decimal value. Either way, nothing a server sends can reach the terminal as a control character.


META OPTIONS
============

`-?`, `--help`
: Displays an overview of the command-line options.

`-v`, `--version`
: Displays the version of dog being invoked.


ENVIRONMENT VARIABLES
=====================

dog responds to the following environment variables:

## `DOG_DEBUG`

Set this to any non-empty value to have dog emit debugging information to standard error. For more in-depth output, set this to the exact string ‘`trace`’. The log is coloured only when standard error is a terminal.

## `NO_COLOR`

Set this to anything but the empty string to turn off automatic colours. ‘`--colour=always`’ still turns them on.

## `TERM`

When this is ‘`dumb`’, automatic colours are off.

## `SSL_CERT_FILE`, `SSL_CERT_DIR`

The system’s OpenSSL, which checks the certificates of DNS-over-TLS and DNS-over-HTTPS servers, reads the certificates it trusts from these instead of from its own defaults, if they are set.


RECORD TYPES
============

dog understands and can interpret the following record types:

`A`
: IPv4 addresses

`AAAA`
: IPv6 addresses

`CAA`
: permitted certificate authorities

`CNAME`
: canonical domain aliases

`DNSKEY`
: DNSSEC public keys

`DS`
: DNSSEC delegation signers

`EUI48`, `EUI64`
: 48-bit and 64-bit extended unique identifiers

`HINFO`
: system information and, sometimes, forbidden request explanations

`LOC`
: location information

`MX`
: e-mail server addresses

`NAPTR`
: DDDS rules

`NS`
: domain name servers

`NSEC`
: DNSSEC authenticated denial of existence

`OPENPGPKEY`
: OpenPGP public keys

`OPT`
: extensions to the DNS protocol

`PTR`
: pointers to canonical names, usually for reverse lookups

`RRSIG`
: DNSSEC signatures

`SOA`
: administrative information about zones

`SRV`
: IP addresses with port numbers

`SSHFP`
: SSH key fingerprints

`TLSA`
: TLS certificates, public keys, and hashes

`TXT`
: arbitrary textual information

`URI`
: URIs

When a response DNS packet contains a record of one of these known types, dog will display it in a table containing the type name and a human-readable summary of its contents.

Records with a type number that does not map to any known record type will still be displayed. As they cannot be interpreted, their contents will be displayed as a series of numbers instead.

dog also contains a list of record type names that it knows the type number of, but is not able to interpret, such as `IXFR` or `ANY` or `AFSDB`. These are acceptable as command-line arguments, meaning you can send an AFSDB request with ‘`dog AFSDB`’. However, their response contents will still be displayed as numbers. They may be supported in future versions of dog.


PROTOCOL TWEAKS
===============

The `-Z` command-line argument can be used one or more times to set some protocol-level options in the DNS queries that get sent. It accepts the following values:

`aa`, `authoritative`
: Sets the `AA` (Authoritative Answer) bit in the query.

`ad`, `authentic`
: Sets the `AD` (Authentic Data) bit in the query.

`bufsize=NUM`
: Sets the UDP payload size field in the OPT record of the query. The OPT record carries it, so this cannot be used with ‘`--edns disable`’.

`cd`, `checking-disabled`
: Sets the `CD` (Checking Disabled) bit in the query.

`do`, `dnssec-ok`
: Sets the `DO` (DNSSEC OK) bit in the OPT record of the query, asking for DNSSEC records. This cannot be used with ‘`--edns disable`’ either.


EXIT STATUSES
=============

0
: If everything goes OK.

1
: If there was a network, I/O, TLS, HTTP, or protocol error during operation, including a server that did not answer in time.

2
: If there is no result from the server when running in short mode. This can be any received server error, not just NXDOMAIN, or a query that failed.

3
: If there was a problem with the command-line arguments.

4
: If there was a problem obtaining the system nameserver information, or the output could not be written.


AUTHOR
======

dog is maintained by Benjamin ‘ogham’ Sago.

**Website:** `https://dns.lookup.dog/` \
**Source code:** `https://github.com/ogham/dog`
