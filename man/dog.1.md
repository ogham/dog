% dog(1) v0.9.0

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

Set this to a non-empty value to have dog emit debugging information to standard error.


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


AUTHOR
======

dog is maintained by Benjamin ‘ogham’ Sago.

**Website:** `https://dns.lookup.dog/` \
**Source code:** `https://github.com/ogham/dog`
