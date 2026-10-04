#!/usr/bin/env python3
"""Capture real DNS and DNS-over-HTTPS responses as dog's test fixtures.

dog's tests must be backed by what real servers actually send, not by bytes
invented to match the code's assumptions. This script builds each query
byte-for-byte the way dog does (see `Request::to_bytes` in dns/src/wire.rs),
sends it to a real server, and stores the query and the raw response under
tests/fixtures/, with one row per scenario in tests/fixtures/MANIFEST.tsv.

Tier 1 scenarios query public servers over the internet. Tier 2 scenarios
query a local BIND 9 container serving tests/capture/bind/, for record types
and protocol behaviour that no public server reliably provides. Either way
the response bytes are encoded by a real DNS server, never by hand.

Usage:
    capture.py                 capture every scenario
    capture.py --tier 2        capture only one tier
    capture.py --only NAME...  capture only the named scenarios
    capture.py --list          list the scenario names

Exits non-zero if any scenario fails, or if a response does not look like
what its scenario expects, so a fixture can never silently stop testing
the thing it was captured for. Needs python3 (stdlib only), dig (for the
text oracle), and docker (for tier 2).
"""

import argparse
import datetime
import pathlib
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
MANIFEST = FIXTURES / "MANIFEST.tsv"
BIND_DIR = ROOT / "tests" / "capture" / "bind"
BIND_IMAGE = "internetsystemsconsortium/bind9:9.20"
BIND_CONTAINER = "dog-fixture-bind"
BIND_PORT = 15353

# Must match USER_AGENT in dns-transport/src/https.rs.
USER_AGENT = "dog/0.2.0-pre"
TIMEOUT = 5.0

# HTTP/2 (RFC 9113), as far as dns-transport/src/h2.rs uses it.
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, RST_STREAM, SETTINGS, PING, GOAWAY = 0x0, 0x1, 0x3, 0x4, 0x6, 0x7
END_STREAM, ACK, END_HEADERS, PADDED, PRIORITY = 0x1, 0x1, 0x4, 0x8, 0x20

# The :status entries of the HPACK static table (RFC 7541 appendix A).
STATIC_STATUS = {8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}

# The Huffman codes of the digits (RFC 7541 appendix B), as (code, bit length).
HUFFMAN_DIGITS = {
    (0b00000, 5): "0", (0b00001, 5): "1", (0b00010, 5): "2", (0b011001, 6): "3", (0b011010, 6): "4",
    (0b011011, 6): "5", (0b011100, 6): "6", (0b011101, 6): "7", (0b011110, 6): "8", (0b011111, 6): "9",
}

QTYPES = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "HINFO": 13, "MX": 15,
    "TXT": 16, "AAAA": 28, "LOC": 29, "SRV": 33, "NAPTR": 35, "OPT": 41,
    "DS": 43, "SSHFP": 44, "RRSIG": 46, "NSEC": 47, "DNSKEY": 48, "TLSA": 52,
    "OPENPGPKEY": 61, "HTTPS": 65, "EUI48": 108, "EUI64": 109, "URI": 256,
    "CAA": 257,
}
QCLASSES = {"IN": 1, "CH": 3, "HS": 4}

MANIFEST_COLUMNS = [
    "name", "tier", "transport", "server", "port", "qname", "qtype", "qclass",
    "knobs", "txid", "response_bytes", "captured_utc", "source",
]

NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED, BADVERS = 0, 1, 2, 3, 4, 5, 16


class CaptureError(Exception):
    """A scenario could not be captured."""


@dataclass
class Expect:
    """What a captured response must look like to be worth keeping."""
    rcode: Optional[int] = None        # extended rcode: header bits plus OPT high bits
    tc: Optional[bool] = None
    answer: Optional[str] = None       # a record of this type is in the answer section
    http_status: Optional[int] = None


@dataclass
class Scenario:
    """One query sent to one server, and what its response should contain."""
    name: str
    tier: int
    transport: str                     # "udp", "tcp", "doh" (HTTP/1.1) or "doh2" (HTTP/2)
    server: str
    qname: str = ""
    qtype: str = "A"
    qclass: str = "IN"
    port: int = 53
    edns: bool = True
    do: bool = False
    bufsize: int = 512                 # dog's default OPT payload size
    edns_version: int = 0
    rd: bool = True
    opcode: int = 0
    qdcount: int = 1
    path: str = "/dns-query"
    body: Optional[bytes] = None       # DoH body sent instead of the DNS query
    content_type: str = "application/dns-message"  # sent with HTTP/2 DoH requests
    expect: Expect = field(default_factory=Expect)

    def knobs(self):
        knobs = [
            f"edns={int(self.edns)}", f"do={int(self.do)}", f"bufsize={self.bufsize}",
            f"version={self.edns_version}", f"rd={int(self.rd)}", f"opcode={self.opcode}",
            f"qdcount={self.qdcount}", f"path={self.path if self.transport.startswith('doh') else '-'}",
        ]
        if self.transport == "doh2":
            knobs.append(f"content-type={self.content_type}")
        return ",".join(knobs)


def public_udp(name, qname, qtype, server="1.1.1.1", **kw):
    return Scenario(name, 1, "udp", server, qname, qtype, **kw)


def public_tcp(name, qname, qtype, server="1.1.1.1", **kw):
    return Scenario(name, 1, "tcp", server, qname, qtype, **kw)


def bind(name, qname, qtype, transport="udp", **kw):
    return Scenario(name, 2, transport, "127.0.0.1", qname, qtype, port=BIND_PORT, **kw)


def doh(name, host, qname="a-example.lookup.dog", **kw):
    return Scenario(name, 1, "doh", host, qname, "A", port=443, **kw)


def doh2(name, host, qname="a-example.lookup.dog", **kw):
    return Scenario(name, 1, "doh2", host, qname, "A", port=443, **kw)


def answers(qtype, rcode=NOERROR):
    return Expect(rcode=rcode, answer=qtype)


DNSSEC = {"do": True, "bufsize": 1232}

SCENARIOS = [
    # lookup.dog is dog's own example zone, also used by xtests/live.
    public_udp("a-example", "a-example.lookup.dog", "A", expect=answers("A")),
    public_udp("aaaa-example", "aaaa-example.lookup.dog", "AAAA", expect=answers("AAAA")),
    public_udp("caa-example", "caa-example.lookup.dog", "CAA", expect=answers("CAA")),
    public_udp("cname-example", "cname-example.lookup.dog", "CNAME", expect=answers("CNAME")),
    public_udp("a-via-cname", "cname-example.lookup.dog", "A", expect=answers("CNAME")),
    public_udp("hinfo-example", "hinfo-example.lookup.dog", "HINFO", expect=answers("HINFO")),
    public_udp("mx-example", "mx-example.lookup.dog", "MX", expect=answers("MX")),
    public_udp("ns-lookup-dog", "lookup.dog", "NS", expect=answers("NS")),
    public_udp("soa-lookup-dog", "lookup.dog", "SOA", expect=answers("SOA")),
    public_udp("srv-example", "srv-example.lookup.dog", "SRV", expect=answers("SRV")),
    public_udp("txt-example", "txt-example.lookup.dog", "TXT", expect=answers("TXT")),
    public_udp("nxdomain", "non.existent", "A", expect=Expect(rcode=NXDOMAIN)),
    public_tcp("a-example-tcp", "a-example.lookup.dog", "A", expect=answers("A")),
    public_udp("a-example-google", "a-example.lookup.dog", "A", server="8.8.8.8", expect=answers("A")),
    public_udp("a-dns-google", "dns.google", "A", expect=answers("A")),

    # Other record types with stable public data.
    public_udp("ptr-one-one", "1.1.1.1.in-addr.arpa", "PTR", expect=answers("PTR")),
    public_udp("loc-caida", "caida.org", "LOC", expect=answers("LOC")),
    public_udp("naptr-sip2sip", "sip2sip.info", "NAPTR", expect=answers("NAPTR")),
    public_udp("tlsa-ietf-mail", "_25._tcp.mail.ietf.org", "TLSA", expect=answers("TLSA")),
    public_udp("uri-fedora", "_kerberos.fedoraproject.org", "URI", expect=answers("URI")),
    public_udp("https-cloudflare", "cloudflare.com", "HTTPS", expect=answers("HTTPS")),

    # DNSSEC.
    public_udp("dnskey-cloudflare", "cloudflare.com", "DNSKEY", expect=answers("DNSKEY"), **DNSSEC),
    public_udp("ds-cloudflare", "cloudflare.com", "DS", expect=answers("DS"), **DNSSEC),
    public_udp("rrsig-cloudflare", "cloudflare.com", "A", expect=answers("RRSIG"), **DNSSEC),
    public_udp("nsec-ietf", "ietf.org", "NSEC", expect=answers("NSEC"), **DNSSEC),
    public_udp("nsec-denial-cloudflare", "dogtest-nonexistent.cloudflare.com", "A", **DNSSEC),
    public_tcp("dnskey-root-tcp", ".", "DNSKEY", do=True, bufsize=65535, expect=answers("DNSKEY")),

    # Error responses and truncation.
    public_udp("servfail-dnssec-failed", "dnssec-failed.org", "A", expect=Expect(rcode=SERVFAIL)),
    public_udp("refused-no-recursion", "example.com", "A", server="ns1.google.com", rd=False,
               expect=Expect(rcode=REFUSED)),
    public_udp("ch-txt-id-server", "id.server", "TXT", qclass="CH"),
    public_udp("notimp-opcode-status", "a-example.lookup.dog", "A", server="8.8.8.8", opcode=2,
               expect=Expect(rcode=NOTIMP)),
    public_udp("tc-txt-google", "google.com", "TXT", edns=False, expect=Expect(tc=True)),
    public_tcp("tc-txt-google-tcp", "google.com", "TXT", edns=False,
               expect=Expect(rcode=NOERROR, tc=False, answer="TXT")),

    # DNS-over-HTTPS: the raw HTTP/1.1 exchange, exactly as dog sends it.
    doh("doh-cloudflare", "cloudflare-dns.com", expect=Expect(http_status=200, answer="A")),
    doh("doh-google", "dns.google", expect=Expect(http_status=200, answer="A")),
    doh("doh-google-404", "dns.google", path="/nope", expect=Expect(http_status=404)),
    doh("doh-google-400", "dns.google", body=b"\x00\x01not a DNS message",
        expect=Expect(http_status=400)),
    doh("doh-httpbin-500", "eu.httpbin.org", path="/status/500", expect=Expect(http_status=500)),
    doh("doh-httpbin-200", "eu.httpbin.org", path="/status/200", expect=Expect(http_status=200)),

    # Tier 2: a local BIND 9 serving tests/capture/bind/dogtest.example.zone.
    bind("a-bind", "a.dogtest.example", "A", expect=answers("A")),
    bind("aaaa-bind", "aaaa.dogtest.example", "AAAA", expect=answers("AAAA")),
    bind("soa-bind", "dogtest.example", "SOA", expect=answers("SOA")),
    bind("eui48", "eui48.dogtest.example", "EUI48", expect=answers("EUI48")),
    bind("eui64", "eui64.dogtest.example", "EUI64", expect=answers("EUI64")),
    bind("sshfp", "sshfp.dogtest.example", "SSHFP", expect=answers("SSHFP")),
    bind("openpgpkey", "openpgpkey.dogtest.example", "OPENPGPKEY", expect=answers("OPENPGPKEY")),
    bind("caa-flags", "caa.dogtest.example", "CAA", expect=answers("CAA")),
    bind("loc-bind", "loc.dogtest.example", "LOC", expect=answers("LOC")),
    bind("loc-south-east", "loc-se.dogtest.example", "LOC", expect=answers("LOC")),
    bind("naptr-bind", "naptr.dogtest.example", "NAPTR", expect=answers("NAPTR")),
    bind("uri-bind", "_http._tcp.dogtest.example", "URI", expect=answers("URI")),
    bind("tlsa-bind", "_443._tcp.dogtest.example", "TLSA", expect=answers("TLSA")),
    bind("hinfo-bind", "hinfo.dogtest.example", "HINFO", expect=answers("HINFO")),
    bind("srv-bind", "_sip._udp.dogtest.example", "SRV", expect=answers("SRV")),
    bind("ptr-bind", "ptr.dogtest.example", "PTR", expect=answers("PTR")),
    bind("mx-null", "nullmx.dogtest.example", "MX", expect=answers("MX")),
    bind("txt-escapes", "escapes.dogtest.example", "TXT", expect=answers("TXT")),
    bind("txt-unicode", "unicode.dogtest.example", "TXT", expect=answers("TXT")),
    bind("txt-multi", "multi.dogtest.example", "TXT", expect=answers("TXT")),
    bind("cname-bind", "alias.dogtest.example", "A", expect=answers("CNAME")),
    bind("unknown-type-bind", "unknown.dogtest.example", "TYPE65280", expect=answers("TYPE65280")),
    bind("txt-big-udp", "big.dogtest.example", "TXT", bufsize=4096, expect=Expect(tc=True)),
    bind("txt-big-tcp", "big.dogtest.example", "TXT", transport="tcp", bufsize=4096,
         expect=Expect(rcode=NOERROR, tc=False, answer="TXT")),
    bind("nxdomain-bind", "missing.dogtest.example", "A", expect=Expect(rcode=NXDOMAIN)),
    bind("refused-bind", "example.com", "A", expect=Expect(rcode=REFUSED)),
    bind("badvers-bind", "a.dogtest.example", "A", edns_version=1, expect=Expect(rcode=BADVERS)),
    bind("formerr-bind", "a.dogtest.example", "A", qdcount=2, expect=Expect(rcode=FORMERR)),
    bind("notimp-bind", "a.dogtest.example", "A", opcode=2, expect=Expect(rcode=NOTIMP)),
    bind("version-bind", "version.bind", "TXT", qclass="CH", expect=answers("TXT")),
    bind("hs-class-bind", "a.dogtest.example", "A", qclass="HS", expect=Expect(rcode=REFUSED)),

    # DNS-over-HTTPS over HTTP/2, which a server picks by ALPN, and which
    # Quad9 insists on. These come last so earlier transaction IDs stay put.
    doh2("doh2-cloudflare", "cloudflare-dns.com", expect=Expect(http_status=200, answer="A")),
    doh2("doh2-google", "dns.google", expect=Expect(http_status=200, answer="A")),
    doh2("doh2-quad9", "dns.quad9.net", expect=Expect(http_status=200, answer="A")),
    doh2("doh2-google-404", "dns.google", path="/nope", expect=Expect(http_status=404)),
    doh2("doh2-google-415", "dns.google", content_type="text/plain", expect=Expect(http_status=415)),
    doh2("doh2-cloudflare-415", "cloudflare-dns.com", content_type="text/plain", expect=Expect(http_status=415)),
]

INDEX = {s.name: i for i, s in enumerate(SCENARIOS)}


def type_number(qtype):
    if qtype.startswith("TYPE"):
        return int(qtype[4:])
    return QTYPES[qtype]


def txid_for(scenario):
    """A fixed, per-scenario transaction ID, so captures are reproducible."""
    return 0x1000 + INDEX[scenario.name]


# ---- building queries the way dog does ----

def encode_name(name):
    out = b""
    for label in name.split("."):
        if label:
            raw = label.encode("ascii")
            out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_query(s, txid):
    """Encodes the scenario's query exactly as dog's `Request::to_bytes` would."""
    flags = (s.opcode << 11) | (0x0100 if s.rd else 0)
    arcount = 1 if s.edns else 0
    question = encode_name(s.qname) + struct.pack(">HH", type_number(s.qtype), QCLASSES[s.qclass])
    query = struct.pack(">6H", txid, flags, s.qdcount, 0, 0, arcount) + question * s.qdcount
    if s.edns:
        edns_flags = 0x8000 if s.do else 0
        query += b"\x00" + struct.pack(">HHBBHH", QTYPES["OPT"], s.bufsize, 0, s.edns_version, edns_flags, 0)
    return query


# ---- sending ----

def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise CaptureError(f"connection closed after {len(data)} of {count} bytes")
        data += chunk
    return data


def send_udp(host, port, query):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(65535)
        return data


def send_tcp(host, port, query):
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        sock.sendall(struct.pack(">H", len(query)) + query)
        (length,) = struct.unpack(">H", recv_exact(sock, 2))
        return recv_exact(sock, length)


def build_doh_request(host, path, body):
    """The HTTP/1.1 request dog's HTTPS transport sends (dns-transport/src/https.rs)."""
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n"
    )
    return head.encode("ascii") + body


def header_value(head, name):
    for line in head.split(b"\r\n")[1:]:
        key, sep, value = line.partition(b":")
        if sep and key.strip().lower() == name:
            return value.strip()
    return None


def read_until(sock, data, done):
    while not done(data):
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            # A close-delimited body has no other end marker; the server
            # going quiet is how it ends.
            print("  (read ended by timeout)", file=sys.stderr)
            break
        if not chunk:
            break
        data += chunk
    return data


def read_http_response(sock):
    data = read_until(sock, b"", lambda buf: b"\r\n\r\n" in buf)
    end = data.find(b"\r\n\r\n") + 4
    if end < 4:
        raise CaptureError("connection closed before the HTTP headers ended")
    length = header_value(data[:end], b"content-length")
    if length is not None:
        return read_until(sock, data, lambda buf: len(buf) - end >= int(length))
    if (header_value(data[:end], b"transfer-encoding") or b"").lower() == b"chunked":
        return read_until(sock, data, lambda buf: buf.endswith(b"0\r\n\r\n"))
    return read_until(sock, data, lambda buf: False)


def https_exchange(host, port, request):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(request)
            return read_http_response(tls)


def h2_frame(kind, flags, stream, payload):
    return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", stream) + payload


def hpack_integer(value, prefix_bits, flags=0):
    """An integer with an N-bit prefix (RFC 7541 §5.1)."""
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([flags | value])
    out = [flags | limit]
    value -= limit
    while value >= 128:
        out.append(value % 128 | 0x80)
        value //= 128
    return bytes(out + [value])


def hpack_literal(name_index, value):
    """A field with its name from the static table and its value literal, not
    Huffman-coded, and not added to any table (RFC 7541 §6.2.2)."""
    data = value.encode("ascii")
    return hpack_integer(name_index, 4) + hpack_integer(len(data), 7) + data


def build_h2_request(host, path, body, content_type):
    """The HTTP/2 request dog's HTTPS transport sends (dns-transport/src/h2.rs):
    the preface, settings turning off server push, the headers, and the body."""
    block = bytes([0x83, 0x87])  # :method POST and :scheme https, from the static table
    for index, value in ((1, host), (4, path), (31, content_type), (19, "application/dns-message"),
                         (58, USER_AGENT), (28, str(len(body)))):
        block += hpack_literal(index, value)
    return (H2_PREFACE + h2_frame(SETTINGS, 0, 0, struct.pack(">HI", 2, 0))
            + h2_frame(HEADERS, END_HEADERS, 1, block) + h2_frame(DATA, END_STREAM, 1, body))


def recv_some(sock):
    chunk = sock.recv(65536)
    if not chunk:
        raise CaptureError("connection closed before the HTTP/2 response ended")
    return chunk


def ends_response(kind, flags, stream):
    if kind == GOAWAY:
        return True
    return stream == 1 and (kind == RST_STREAM or (kind in (HEADERS, DATA) and flags & END_STREAM))


def read_h2_response(sock):
    """Reads frames, answering SETTINGS and PING frames as dog does, and returns
    every byte the server sent up to the frame that ends the response."""
    data, offset = b"", 0
    while True:
        while len(data) < offset + 9:
            data += recv_some(sock)
        length = int.from_bytes(data[offset:offset + 3], "big")
        kind, flags = data[offset + 3], data[offset + 4]
        stream = int.from_bytes(data[offset + 5:offset + 9], "big") & 0x7FFFFFFF
        end = offset + 9 + length
        while len(data) < end:
            data += recv_some(sock)
        if kind == SETTINGS and not flags & ACK:
            sock.sendall(h2_frame(SETTINGS, ACK, 0, b""))
        elif kind == PING and not flags & ACK:
            sock.sendall(h2_frame(PING, ACK, 0, data[offset + 9:end]))
        if ends_response(kind, flags, stream):
            return data[:end]
        offset = end


def h2_exchange(host, port, request):
    context = ssl.create_default_context()
    context.set_alpn_protocols(["h2"])
    with socket.create_connection((host, port), timeout=TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            if tls.selected_alpn_protocol() != "h2":
                raise CaptureError(f"{host} did not choose HTTP/2")
            tls.sendall(request)
            return read_h2_response(tls)


# ---- checking responses ----

def skip_name(buf, offset):
    while True:
        length = buf[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def iter_records(buf):
    """Yields (section, rtype, ttl) for every resource record in a message."""
    qdcount, ancount, nscount, arcount = struct.unpack(">4H", buf[4:12])
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(buf, offset) + 4
    for section, count in (("answer", ancount), ("authority", nscount), ("additional", arcount)):
        for _ in range(count):
            offset = skip_name(buf, offset)
            rtype, _rclass, ttl, rdlength = struct.unpack(">HHIH", buf[offset:offset + 10])
            offset += 10 + rdlength
            if offset > len(buf):
                raise CaptureError("record data runs past the end of the message")
            yield section, rtype, ttl


def summarise(buf):
    """Returns (extended rcode, set of answer types) for a DNS message."""
    rcode = struct.unpack(">H", buf[2:4])[0] & 0xF
    answer_types = set()
    for section, rtype, ttl in iter_records(buf):
        if section == "answer":
            answer_types.add(rtype)
        if rtype == QTYPES["OPT"]:
            rcode |= (ttl >> 24) << 4
    return rcode, answer_types


def check_dns(s, response, txid):
    if len(response) < 12:
        return ["response is shorter than a DNS header"]
    problems = []
    if struct.unpack(">H", response[:2])[0] != txid:
        problems.append("transaction ID does not match the query")
    truncated = bool(struct.unpack(">H", response[2:4])[0] & 0x0200)
    if s.expect.tc is not None and truncated != s.expect.tc:
        problems.append(f"TC is {truncated}, expected {s.expect.tc}")
    try:
        rcode, answer_types = summarise(response)
    except (struct.error, IndexError, CaptureError) as e:
        return problems + [f"response does not parse: {e}"]
    if s.expect.rcode is not None and rcode != s.expect.rcode:
        problems.append(f"rcode is {rcode}, expected {s.expect.rcode}")
    if s.expect.answer and type_number(s.expect.answer) not in answer_types:
        problems.append(f"no {s.expect.answer} record in the answer section")
    return problems


def http_status(response):
    status_line = response.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2 or not status_line[1].isdigit():
        raise CaptureError(f"not an HTTP response: {response[:40]!r}")
    return int(status_line[1])


def check_http(s, response, txid):
    status = http_status(response)
    if s.expect.http_status is not None and status != s.expect.http_status:
        return [f"HTTP status is {status}, expected {s.expect.http_status}"]
    if s.expect.answer:
        body = response[response.find(b"\r\n\r\n") + 4:]
        return check_dns(s, body, txid)
    return []


def h2_frames(data):
    """Yields (type, flags, stream, payload) for each frame."""
    offset = 0
    while offset + 9 <= len(data):
        length = int.from_bytes(data[offset:offset + 3], "big")
        stream = int.from_bytes(data[offset + 5:offset + 9], "big") & 0x7FFFFFFF
        yield data[offset + 3], data[offset + 4], stream, data[offset + 9:offset + 9 + length]
        offset += 9 + length


def h2_content(kind, flags, payload):
    """A HEADERS or DATA frame's payload without its padding or priority."""
    pad = 0
    if flags & PADDED:
        pad, payload = payload[0], payload[1:]
    if kind == HEADERS and flags & PRIORITY:
        payload = payload[5:]
    return payload[:len(payload) - pad]


def hpack_read_integer(block, at, prefix_bits):
    limit = (1 << prefix_bits) - 1
    value, at = block[at] & limit, at + 1
    shift = 0
    while value >= limit and shift < 64:
        byte, at = block[at], at + 1
        value += (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            break
    return value, at


def huffman_digits(raw):
    out, code, length = "", 0, 0
    for byte in raw:
        for i in range(7, -1, -1):
            code, length = code << 1 | (byte >> i) & 1, length + 1
            if (code, length) in HUFFMAN_DIGITS:
                out, code, length = out + HUFFMAN_DIGITS[(code, length)], 0, 0
    if length >= 8 or code != (1 << length) - 1:
        raise CaptureError(f"status {raw!r} is not Huffman-coded digits")
    return out


def h2_status(block):
    """The :status from the start of a header block, and how it was encoded."""
    at = 0
    while block[at] & 0xE0 == 0x20:  # dynamic table size updates
        _, at = hpack_read_integer(block, at, 5)
    if block[at] & 0x80:
        index, _ = hpack_read_integer(block, at, 7)
        return STATIC_STATUS[index], "indexed"
    index, at = hpack_read_integer(block, at, 6 if block[at] & 0x40 else 4)
    if index not in STATIC_STATUS:
        raise CaptureError(f"the first header field (name index {index}) is not :status")
    huffman = block[at] & 0x80
    length, at = hpack_read_integer(block, at, 7)
    raw = block[at:at + length]
    if huffman:
        return int(huffman_digits(raw)), "literal, Huffman-coded"
    return int(raw.decode("ascii")), "literal"


def h2_status_and_body(response):
    """The status of the response on stream 1, and its body."""
    status, body = None, b""
    for kind, flags, stream, payload in h2_frames(response):
        if stream == 1 and kind == HEADERS and status is None:
            status, how = h2_status(h2_content(kind, flags, payload))
            print(f"  :status {status} ({how})", file=sys.stderr)
        elif stream == 1 and kind == DATA:
            body += h2_content(kind, flags, payload)
    return status, body


def check_h2(s, response, txid):
    status, body = h2_status_and_body(response)
    if status is None:
        return ["no response headers on stream 1"]
    if s.expect.http_status is not None and status != s.expect.http_status:
        return [f"HTTP/2 status is {status}, expected {s.expect.http_status}"]
    if s.expect.answer:
        return check_dns(s, body, txid)
    return []


# ---- the dig text oracle ----

def dig_flags(s):
    flags = ["+tcp"] if s.transport == "tcp" else ["+ignore"]
    flags.append("+noedns" if not s.edns else f"+bufsize={s.bufsize}")
    if s.do:
        flags.append("+dnssec")
    if not s.rd:
        flags.append("+norecurse")
    return flags


def dig_oracle(s):
    """dig's view of the same query, as an independent reading of the answer."""
    if s.opcode or s.qdcount != 1 or s.edns_version:
        return None  # dig cannot send these queries
    command = ["dig", f"@{s.server}", "-p", str(s.port), "-c", s.qclass, "-t", s.qtype, s.qname,
               "+noall", "+answer", "+authority", "+nottlid", "+time=5", "+tries=1"] + dig_flags(s)
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise CaptureError(f"dig exited {result.returncode}: {result.stderr.strip()}")
    return result.stdout


# ---- capturing ----

def write_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def manifest_row(s, txid, response, source):
    return {
        "name": s.name, "tier": str(s.tier), "transport": s.transport, "server": s.server,
        "port": str(s.port), "qname": s.qname, "qtype": s.qtype, "qclass": s.qclass,
        "knobs": s.knobs(), "txid": f"0x{txid:04x}", "response_bytes": str(len(response)),
        "captured_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": source,
    }


def capture_dns(s, txid, source):
    query = build_query(s, txid)
    send = send_tcp if s.transport == "tcp" else send_udp
    response = send(s.server, s.port, query)
    problems = check_dns(s, response, txid)
    if problems:
        return None, problems
    oracle = dig_oracle(s)
    base = FIXTURES / "dns" / s.name
    write_bytes(base.with_suffix(".query.bin"), query)
    write_bytes(base.with_suffix(".response.bin"), response)
    if oracle is not None:
        write_bytes(base.with_suffix(".dig.txt"), oracle.encode("utf-8"))
    return manifest_row(s, txid, response, source), []


def capture_doh(s, txid, source):
    body = s.body if s.body is not None else build_query(s, txid)
    request = build_doh_request(s.server, s.path, body)
    response = https_exchange(s.server, s.port, request)
    problems = check_http(s, response, txid)
    if problems:
        return None, problems
    base = FIXTURES / "doh" / s.name
    write_bytes(base.with_suffix(".request.http"), request)
    write_bytes(base.with_suffix(".response.http"), response)
    return manifest_row(s, txid, response, source), []


def capture_doh2(s, txid, source):
    body = s.body if s.body is not None else build_query(s, txid)
    request = build_h2_request(s.server, s.path, body, s.content_type)
    response = h2_exchange(s.server, s.port, request)
    problems = check_h2(s, response, txid)
    if problems:
        return None, problems
    base = FIXTURES / "doh" / s.name
    write_bytes(base.with_suffix(".request.h2"), request)
    write_bytes(base.with_suffix(".response.h2"), response)
    return manifest_row(s, txid, response, source), []


def capture_one(s, sources):
    txid = txid_for(s)
    source = sources[s.tier]
    if s.transport == "doh":
        return capture_doh(s, txid, source)
    if s.transport == "doh2":
        return capture_doh2(s, txid, source)
    return capture_dns(s, txid, source)


def capture_all(scenarios, sources):
    rows, failures = [], []
    for s in scenarios:
        print(f"{s.name}: {s.qtype} {s.qname or '-'} via {s.transport} {s.server}:{s.port}", file=sys.stderr)
        try:
            row, problems = capture_one(s, sources)
        except (OSError, ssl.SSLError, CaptureError, subprocess.TimeoutExpired) as e:
            row, problems = None, [str(e)]
        if problems:
            failures.append(f"{s.name}: {'; '.join(problems)}")
        else:
            rows.append(row)
    return rows, failures


# ---- the manifest ----

def read_manifest():
    if not MANIFEST.exists():
        return {}
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return {row["name"]: row for row in (dict(zip(header, line.split("\t"))) for line in lines[1:] if line)}


def update_manifest(new_rows):
    rows = read_manifest()
    rows.update({row["name"]: row for row in new_rows})
    ordered = sorted(rows.values(), key=lambda row: INDEX.get(row["name"], len(INDEX)))
    lines = ["\t".join(MANIFEST_COLUMNS)] + ["\t".join(row[c] for c in MANIFEST_COLUMNS) for row in ordered]
    MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---- the local BIND server (tier 2) ----

def docker(*args, check=True):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise CaptureError(f"docker {args[0]} failed: {result.stderr.strip()}")
    return result


def bind_source():
    digest = docker("image", "inspect", "--format", "{{index .RepoDigests 0}}", BIND_IMAGE).stdout.strip()
    version = docker("run", "--rm", "--entrypoint", "named", BIND_IMAGE, "-v").stdout.strip()
    return f"{version} {digest}"


def start_bind():
    if docker("ps", "-aq", "--filter", f"name=^{BIND_CONTAINER}$").stdout.strip():
        docker("rm", "-f", BIND_CONTAINER)
    docker("run", "-d", "--rm", "--name", BIND_CONTAINER,
           "-p", f"127.0.0.1:{BIND_PORT}:53/udp", "-p", f"127.0.0.1:{BIND_PORT}:53/tcp",
           "-v", f"{BIND_DIR}:/etc/bind:ro", BIND_IMAGE,
           "-f", "-c", "/etc/bind/named.conf")
    probe = build_query(bind("probe", "dogtest.example", "SOA"), 0x0001)
    for _ in range(40):
        try:
            send_udp("127.0.0.1", BIND_PORT, probe)
            return
        except OSError:
            time.sleep(0.25)
    logs = docker("logs", BIND_CONTAINER, check=False)
    raise CaptureError(f"BIND did not start answering:\n{logs.stdout}{logs.stderr}")


def stop_bind():
    result = docker("rm", "-f", BIND_CONTAINER, check=False)
    if result.returncode != 0:
        print(f"warning: could not remove {BIND_CONTAINER}: {result.stderr.strip()}", file=sys.stderr)


# ---- entry point ----

def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", nargs="+", metavar="NAME", help="capture only these scenarios")
    parser.add_argument("--tier", type=int, choices=(1, 2), help="capture only this tier")
    parser.add_argument("--list", action="store_true", help="list the scenario names and exit")
    return parser.parse_args(argv)


def select(args):
    chosen = [s for s in SCENARIOS if args.tier is None or s.tier == args.tier]
    if args.only:
        unknown = sorted(set(args.only) - set(INDEX))
        if unknown:
            raise SystemExit(f"unknown scenario(s): {', '.join(unknown)}")
        chosen = [s for s in chosen if s.name in args.only]
    return chosen


def run(chosen):
    if shutil.which("dig") is None:
        raise SystemExit("dig is required for the text oracle (apt install bind9-dnsutils)")
    needs_bind = any(s.tier == 2 for s in chosen)
    sources = {1: "public server"}
    if needs_bind:
        sources[2] = bind_source()
        start_bind()
    try:
        return capture_all(chosen, sources)
    finally:
        if needs_bind:
            stop_bind()


def main(argv=None):
    args = parse_args(argv)
    chosen = select(args)
    if args.list:
        print("\n".join(f"{s.tier} {s.name}" for s in chosen))
        return 0
    rows, failures = run(chosen)
    update_manifest(rows)
    print(f"captured {len(rows)} of {len(chosen)} scenarios", file=sys.stderr)
    for failure in failures:
        print(f"FAILED {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
