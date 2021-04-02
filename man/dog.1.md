% dog(1) v0.1.0

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


QUERY OPTIONS
=============

`-q`, `--query=HOST`
: Host name or domain name to query.

`-t`, `--type=TYPE`
: Type of the DNS record being queried (`A`, `MX`, `NS`...)

`-n`, `--nameserver=ADDR`
: Address of the nameserver to send packets to.

`--class=CLASS`
: Network class of the DNS record being queried (`IN`, `CH`, `HS`)

By default, dog will request A records using the system default resolver. At least one domain name must be passed — dog will not automatically query the root nameservers.

Query options passed in using a command-line option, such as ‘`--query lookup.dog`’ or ‘`--type MX`’, or as plain arguments, such as ‘`lookup.dog`’ or ‘`MX`’. dog will make an intelligent guess as to what plain arguments mean (`MX` is quite clearly a type), which makes it easier to compose ad-hoc queries quickly. If precision is desired, use the long-form options.

If more than one domain, type, nameserver, or class is specified, dog will perform one query for each combination, and display the combined results in a table. For example, passing three type arguments and two domain name arguments will send six requests.

DNS traditionally uses port 53 for both TCP and UDP. To use a resolver with a different port, include the port number after a colon (`:`) in the nameserver address.


SENDING OPTIONS
===============

`--edns=SETTING`
: Whether to opt in to DNS. This can be ‘`disable`’, ‘`hide`’, or ‘`show`’.

`--txid=NUMBER`
: Set the transaction ID to a specific value.

`-Z=TWEAKS`
: Set uncommon protocol-level tweaks.


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

By default, dog will use the UDP protocol, automatically re-sending the request using TCP if the response indicates that the message is too large for UDP. Passing `--udp` will only use UDP and will fail in this case; passing `--tcp` will use TCP by default.

The DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH) protocols are available with the `--tls` and `--https` options. Bear in mind that the system default resolver is unlikely to respond to requests using these protocols.

Note that if a hostname or domain name is given as a nameserver, rather than an IP address, the resolution of that host is performed by the operating system, _not_ by dog.

Unlike the others, the HTTPS transport type requires an entire URL, complete with protocol, domain name, and path.


OUTPUT OPTIONS
==============

`-1`, `--short`
: Short mode: display nothing but the first result.

`-J`, `--json`
: Display the output as JSON.

`--color`, `--colour=WHEN`
: When to colourise the output. This can be ‘`always`’, ‘`automatic`’, or ‘`never`’.

`--seconds`
: Do not format durations as hours and minutes; instead, display them as seconds.

`--time`
: Print how long the response took to arrive.


META OPTIONS
============

`--help`
: Displays an overview of the command-line options.

`--version`
: Displays the version of dog being invoked.


ENVIRONMENT VARIABLES
=====================

dog responds to the following environment variables:

## `DOG_DEBUG`

Set this to any non-empty value to have dog emit debugging information to standard error. For more in-depth output, set this to the exact string ‘`trace`’.


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

`OPT`
: extensions to the DNS protocol

`PTR`
: pointers to canonical names, usually for reverse lookups

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

When a response DNS packet contains a record of one of these known types, dog will display it in a table containing the type name and a human-readable summary of its contents.

Records with a type number that does not map to any known record type will still be displayed. As they cannot be interpreted, their contents will be displayed as a series of numbers instead.

dog also contains a list of record type names that it knows the type number of, but is not able to interpret, such as `IXFR` or `ANY` or `AFSDB`. These are acceptable as command-line arguments, meaning you can send an AFSDB request with ‘`dog AFSDB`’. However, their response contents will still be displayed as numbers. They may be supported in future versions of dog.


PROTOCOL TWEAKS
===============

The `-Z` command-line argument can be used one or more times to set some protocol-level options in the DNS queries that get sent. It accepts the following values:

`aa`
: Sets the `AA` (Authoritative Answers) bit in the query.

`ad`
: Sets the `AD` (Authentic Data) bit in the query.

`bufsize=NUM`
: Sets the UDP payload size field in the OPT field in the query. This has no effect if EDNS is diabled.

`cd`
: Sets the `CD` (Checking Disabled) bit in the query.


EXIT STATUSES
=============

0
: If everything goes OK.

1
: If there was a network, I/O, or TLS error during operation.

2
: If there is no result from the server when running in short mode. This can be any received server error, not just NXDOMAIN.

3
: If there was a problem with the command-line arguments.

4
: If there was a problem obtaining the system nameserver information.


AUTHOR
======

dog is maintained by Benjamin ‘ogham’ Sago.

**Website:** `https://dns.lookup.dog/` \
**Source code:** `https://github.com/ogham/dog`
