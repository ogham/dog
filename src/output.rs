//! Text and JSON output.

use std::fmt;
use std::time::Duration;
use std::io::{self, IsTerminal};

use dns::{Response, Query, Answer, Labels, QClass, ErrorCode, Flags, Opcode, WireError, MandatedLength};
use dns::record::{Record, RecordType, UnknownQtype, OPT};
use dns_transport::Error as TransportError;
use serde_json::Value as JsonValue;

use crate::colours::{self, Colours};
use crate::stderr;
use crate::table::{Table, Section};


/// How to format the output data.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum OutputFormat {

    /// Format the output as plain text, optionally adding ANSI colours.
    Text(UseColours, TextFormat),

    /// Format the output as one line of plain text.
    Short(TextFormat),

    /// Format the entries as JSON.
    JSON,
}


/// When to use colours in the output.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum UseColours {

    /// Always use colours.
    Always,

    /// Use colours if output is to a terminal; otherwise, do not.
    Automatic,

    /// Never use colours.
    Never,
}

/// Options that govern how text should be rendered in record summaries.
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct TextFormat {

    /// Whether to format TTLs as hours, minutes, and seconds.
    pub format_durations: bool,
}

impl UseColours {

    /// Whether we should use colours or not. This checks whether the user has
    /// overridden the colour setting, and if not, whether output is to a
    /// terminal.
    pub fn should_use_colours(self) -> bool {
        self == Self::Always || (self == Self::Automatic && colours::terminal_wants_colour(io::stdout().is_terminal()))
    }

    /// Creates a palette of colours depending on the user’s wishes or whether
    /// output is to a terminal.
    pub fn palette(self) -> Colours {
        if self.should_use_colours() {
            Colours::pretty()
        }
        else {
            Colours::plain()
        }
    }
}


impl OutputFormat {

    /// Prints the entirety of the output, formatted according to the
    /// settings. If the duration has been measured, it should also be
    /// printed. Returns `false` if there were no results to print, and `true`
    /// otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if standard output cannot be written to, such as
    /// when whatever was reading it has gone away.
    pub fn print(self, responses: Vec<Response>, duration: Option<Duration>) -> io::Result<bool> {
        use std::io::Write;

        let mut out = io::stdout().lock();
        let printed = match self {
            Self::Short(tf) => {
                print_short(&mut out, tf, responses)?
            }
            Self::JSON => {
                print_json(&mut out, responses, duration)?;
                true
            }
            Self::Text(uc, tf) => {
                print_text(&mut out, uc, tf, responses, duration)?;
                true
            }
        };

        out.flush()?;
        Ok(printed)
    }

    /// Print an error that’s ocurred while sending or receiving DNS packets
    /// to standard error.
    pub fn print_error(self, error: TransportError) {
        match self {
            Self::Short(..) | Self::Text(..) => {
                stderr::line(format_args!("Error [{}]: {}", erroneous_phase(&error), error_message(error)));
            }

            Self::JSON => {
                let object = serde_json::json!({
                    "error": true,
                    "error_phase": erroneous_phase(&error),
                    "error_message": error_message(error),
                });

                stderr::line(format_args!("{object}"));
            }
        }
    }
}

/// Writes a summary of every answer, one per line, or prints “No results”
/// if there are none. Returns whether there were any answers.
fn print_short(out: &mut impl io::Write, tf: TextFormat, responses: Vec<Response>) -> io::Result<bool> {
    let all_answers = responses.into_iter().flat_map(|r| r.answers).collect::<Vec<_>>();

    if all_answers.is_empty() {
        stderr::line(format_args!("No results"));
        return Ok(false);
    }

    for answer in all_answers {
        writeln!(out, "{}", answer_summary(tf, answer))?;
    }

    Ok(true)
}

fn answer_summary(tf: TextFormat, answer: Answer) -> String {
    match answer {
        Answer::Standard { record, .. }  => tf.record_payload_summary(record),
        Answer::Pseudo { opt, .. }       => TextFormat::pseudo_record_payload_summary(&opt),
    }
}

/// Writes every response as a single JSON document.
fn print_json(out: &mut impl io::Write, responses: Vec<Response>, duration: Option<Duration>) -> io::Result<()> {
    let responses = responses.into_iter().map(json_response).collect::<Vec<_>>();

    let object = match duration {
        Some(duration) => serde_json::json!({
            "responses": responses,
            "duration": {
                "secs": duration.as_secs(),
                "millis": duration.subsec_millis(),
            },
        }),
        None => serde_json::json!({
            "responses": responses,
        }),
    };

    writeln!(out, "{object}")
}

fn json_response(response: Response) -> JsonValue {
    serde_json::json!({
        "flags": json_flags(response.flags),
        "queries": json_queries(&response.queries),
        "answers": json_answers(response.answers),
        "authorities": json_answers(response.authorities),
        "additionals": json_answers(response.additionals),
    })
}

/// Writes the records of every response as a table, after the status of
/// each response that has an error code.
fn print_text(out: &mut impl io::Write, uc: UseColours, tf: TextFormat, responses: Vec<Response>, duration: Option<Duration>) -> io::Result<()> {
    let mut table = Table::new(uc.palette(), tf);

    for response in responses {
        if let Some(rcode) = response.flags.error_code {
            writeln!(out, "Status: {}", error_code_description(rcode))?;
        }

        for a in response.answers {
            table.add_row(a, Section::Answer);
        }

        for a in response.authorities {
            table.add_row(a, Section::Authority);
        }

        for a in response.additionals {
            table.add_row(a, Section::Additional);
        }
    }

    table.print(out, duration)
}

/// How the status line describes a response’s error code.
fn error_code_description(rcode: ErrorCode) -> String {
    match rcode {
        ErrorCode::FormatError     => "Format Error".into(),
        ErrorCode::ServerFailure   => "Server Failure".into(),
        ErrorCode::NXDomain        => "NXDomain".into(),
        ErrorCode::NotImplemented  => "Not Implemented".into(),
        ErrorCode::QueryRefused    => "Query Refused".into(),
        ErrorCode::BadVersion      => "Bad Version".into(),
        ErrorCode::Private(num)    => format!("Private Reason ({num})"),
        ErrorCode::Other(num)      => format!("Other Failure ({num})"),
    }
}

impl TextFormat {

    /// Formats a summary of a record in a received DNS response. Each record
    /// type contains wildly different data, so the format of the summary
    /// depends on what record it’s for.
    pub fn record_payload_summary(self, record: Record) -> String {
        match record {
            Record::A(a)                 => a.address.to_string(),
            Record::AAAA(aaaa)           => aaaa.address.to_string(),
            Record::CAA(caa)             => Self::caa_summary(&caa),
            Record::CNAME(cname)         => quoted(&cname.domain),
            Record::DNSKEY(dnskey)       => format!("{} {} {} {}", dnskey.flags, dnskey.protocol, dnskey.algorithm, dnskey.base64_public_key()),
            Record::DS(ds)               => format!("{} {} {} {}", ds.key_tag, ds.algorithm, ds.digest_type, ds.hex_digest()),
            Record::EUI48(eui48)         => format!("{:?}", eui48.formatted_address()),
            Record::EUI64(eui64)         => format!("{:?}", eui64.formatted_address()),
            Record::HINFO(hinfo)         => format!("{} {}", Ascii(&hinfo.cpu), Ascii(&hinfo.os)),
            Record::LOC(loc)             => Self::loc_summary(&loc),
            Record::MX(mx)               => format!("{} {}", mx.preference, quoted(&mx.exchange)),
            Record::NAPTR(naptr)         => Self::naptr_summary(&naptr),
            Record::NS(ns)               => quoted(&ns.nameserver),
            Record::NSEC(nsec)           => format!("{} {}", quoted(&nsec.next_domain), nsec.type_names().join(" ")),
            Record::OPENPGPKEY(opgp)     => format!("{:?}", opgp.base64_key()),
            Record::PTR(ptr)             => quoted(&ptr.cname),
            Record::RRSIG(rrsig)         => Self::rrsig_summary(&rrsig),
            Record::SSHFP(sshfp)         => format!("{} {} {}", sshfp.algorithm, sshfp.fingerprint_type, sshfp.hex_fingerprint()),
            Record::SOA(soa)             => self.soa_summary(&soa),
            Record::SRV(srv)             => format!("{} {} {}:{}", srv.priority, srv.weight, quoted(&srv.target), srv.port),
            Record::TLSA(tlsa)           => format!("{} {} {} {:?}", tlsa.certificate_usage, tlsa.selector, tlsa.matching_type, tlsa.hex_certificate_data()),
            Record::TXT(txt)             => txt.messages.iter().map(|t| Ascii(t).to_string()).collect::<Vec<_>>().join(", "),
            Record::URI(uri)             => format!("{} {} {}", uri.priority, uri.weight, Ascii(&uri.target)),
            Record::Other { bytes, .. }  => format!("{bytes:?}"),
        }
    }

    fn caa_summary(caa: &dns::record::CAA) -> String {
        let criticality = if caa.critical { "critical" } else { "non-critical" };
        format!("{} {} ({})", Ascii(&caa.tag), Ascii(&caa.value), criticality)
    }

    fn loc_summary(loc: &dns::record::LOC) -> String {
        format!("{} ({}, {}) ({}, {}, {})",
            loc.size,
            loc.horizontal_precision,
            loc.vertical_precision,
            loc.latitude .as_ref().map_or_else(|| "Out of range".into(), ToString::to_string),
            loc.longitude.as_ref().map_or_else(|| "Out of range".into(), ToString::to_string),
            loc.altitude,
        )
    }

    fn naptr_summary(naptr: &dns::record::NAPTR) -> String {
        format!("{} {} {} {} {} {}",
            naptr.order,
            naptr.preference,
            Ascii(&naptr.flags),
            Ascii(&naptr.service),
            Ascii(&naptr.regex),
            quoted(&naptr.replacement),
        )
    }

    fn rrsig_summary(rrsig: &dns::record::RRSIG) -> String {
        format!("{} {} {} {} {}",
            rrsig.type_covered_name().unwrap_or("?"),
            rrsig.algorithm,
            rrsig.key_tag,
            quoted(&rrsig.signer_name),
            rrsig.base64_signature(),
        )
    }

    fn soa_summary(self, soa: &dns::record::SOA) -> String {
        format!("{} {} {} {} {} {} {}",
            quoted(&soa.mname),
            quoted(&soa.rname),
            soa.serial,
            self.format_duration(soa.refresh_interval),
            self.format_duration(soa.retry_interval),
            self.format_duration(soa.expire_limit),
            self.format_duration(soa.minimum_ttl),
        )
    }

    /// Formats a summary of an OPT pseudo-record. Pseudo-records have a different
    /// structure than standard ones.
    pub fn pseudo_record_payload_summary(opt: &OPT) -> String {
        format!("{} {} {} {} {:?}",
            opt.udp_payload_size,
            opt.higher_bits,
            opt.edns0_version,
            opt.flags,
            opt.data)
    }

    /// Formats a duration depending on whether it should be displayed as
    /// seconds, or as computed units.
    pub fn format_duration(self, seconds: u32) -> String {
        if self.format_durations {
            format_duration_hms(seconds)
        }
        else {
            format!("{seconds}")
        }
    }
}

/// A name in quotes. The name escapes anything that is not printable, and
/// any quote or backslash, itself, so it is written as it is; formatting it
/// with `{:?}` as before escaped those escapes a second time.
fn quoted(name: &Labels) -> String {
    format!("\"{name}\"")
}

/// Formats a duration as days, hours, minutes, and seconds, skipping leading
/// zero units.
fn format_duration_hms(seconds: u32) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    }
    else if seconds < 60 * 60 {
        format!("{}m{:02}s",
            seconds / 60,
            seconds % 60)
    }
    else if seconds < 60 * 60 * 24 {
        format!("{}h{:02}m{:02}s",
            seconds / 3600,
            (seconds % 3600) / 60,
            seconds % 60)
    }
    else {
        format!("{}d{}h{:02}m{:02}s",
            seconds / 86400,
            (seconds % 86400) / 3600,
            (seconds % 3600) / 60,
            seconds % 60)
    }
}

/// Serialises DNS response flags as a JSON value.
fn json_flags(flags: Flags) -> JsonValue {
    serde_json::json!({
        "qr"     : flags.response,
        "opcode" : json_opcode(flags.opcode),
        "aa"     : flags.authoritative,
        "tc"     : flags.truncated,
        "rd"     : flags.recursion_desired,
        "ra"     : flags.recursion_available,
        "ad"     : flags.authentic_data,
        "cd"     : flags.checking_disabled,
        "rcode"  : json_rcode(flags.error_code),
    })
}

fn json_opcode(opcode: Opcode) -> JsonValue {
    match opcode {
        Opcode::Query    => "QUERY".into(),
        Opcode::Other(n) => n.into(),
    }
}

fn json_rcode(error_code: Option<ErrorCode>) -> JsonValue {
    match error_code {
        None                            => "NOERROR".into(),
        Some(ErrorCode::FormatError)    => "FORMERR".into(),
        Some(ErrorCode::ServerFailure)  => "SERVFAIL".into(),
        Some(ErrorCode::NXDomain)       => "NXDOMAIN".into(),
        Some(ErrorCode::NotImplemented) => "NOTIMP".into(),
        Some(ErrorCode::QueryRefused)   => "REFUSED".into(),
        Some(ErrorCode::BadVersion)     => "BADVERS".into(),
        Some(ErrorCode::Other(n) | ErrorCode::Private(n)) => n.into(),
    }
}

/// Serialises multiple DNS queries as a JSON value.
fn json_queries(queries: &[Query]) -> JsonValue {
    queries.iter().map(|q| serde_json::json!({
        "name": q.qname.to_string(),
        "class": json_class(q.qclass),
        "type": json_record_type_name(q.qtype),
    })).collect()
}

/// Serialises multiple received DNS answers as a JSON value.
fn json_answers(answers: Vec<Answer>) -> JsonValue {
    answers.into_iter().map(json_answer).collect()
}

fn json_answer(answer: Answer) -> JsonValue {
    match answer {
        Answer::Standard { qname, qclass, ttl, record } => serde_json::json!({
            "name": qname.to_string(),
            "class": json_class(qclass),
            "ttl": ttl,
            "type": json_record_name(&record),
            "data": json_record_data(record),
        }),
        Answer::Pseudo { qname, opt } => serde_json::json!({
            "name": qname.to_string(),
            "type": "OPT",
            "data": {
                "udp_payload_size": opt.udp_payload_size,
                "extended_rcode_bits": opt.higher_bits,
                "version": opt.edns0_version,
                "flags": opt.flags,
                "dnssec_ok": opt.flags & 0x8000 != 0,
                "data": opt.data,
            },
        }),
    }
}


fn json_class(class: QClass) -> JsonValue {
    match class {
        QClass::IN        => "IN".into(),
        QClass::CH        => "CH".into(),
        QClass::HS        => "HS".into(),
        QClass::Other(n)  => n.into(),
    }
}


/// Serialises a DNS record type name.
fn json_record_type_name(record: RecordType) -> JsonValue {
    match record {
        RecordType::A           => "A".into(),
        RecordType::AAAA        => "AAAA".into(),
        RecordType::CAA         => "CAA".into(),
        RecordType::CNAME       => "CNAME".into(),
        RecordType::DNSKEY      => "DNSKEY".into(),
        RecordType::DS          => "DS".into(),
        RecordType::EUI48       => "EUI48".into(),
        RecordType::EUI64       => "EUI64".into(),
        RecordType::HINFO       => "HINFO".into(),
        RecordType::LOC         => "LOC".into(),
        RecordType::MX          => "MX".into(),
        RecordType::NAPTR       => "NAPTR".into(),
        RecordType::NS          => "NS".into(),
        RecordType::NSEC        => "NSEC".into(),
        RecordType::OPENPGPKEY  => "OPENPGPKEY".into(),
        RecordType::PTR         => "PTR".into(),
        RecordType::RRSIG       => "RRSIG".into(),
        RecordType::SOA         => "SOA".into(),
        RecordType::SRV         => "SRV".into(),
        RecordType::SSHFP       => "SSHFP".into(),
        RecordType::TLSA        => "TLSA".into(),
        RecordType::TXT         => "TXT".into(),
        RecordType::URI         => "URI".into(),
        RecordType::Other(unknown) => {
            match unknown {
                UnknownQtype::HeardOf(name, _)  => (*name).into(),
                UnknownQtype::UnheardOf(num)    => (num).into(),
            }
        }
    }
}

/// Serialises a DNS record type name.
fn json_record_name(record: &Record) -> JsonValue {
    match record {
        Record::A(_)           => "A".into(),
        Record::AAAA(_)        => "AAAA".into(),
        Record::CAA(_)         => "CAA".into(),
        Record::CNAME(_)       => "CNAME".into(),
        Record::DNSKEY(_)      => "DNSKEY".into(),
        Record::DS(_)          => "DS".into(),
        Record::EUI48(_)       => "EUI48".into(),
        Record::EUI64(_)       => "EUI64".into(),
        Record::HINFO(_)       => "HINFO".into(),
        Record::LOC(_)         => "LOC".into(),
        Record::MX(_)          => "MX".into(),
        Record::NAPTR(_)       => "NAPTR".into(),
        Record::NS(_)          => "NS".into(),
        Record::NSEC(_)        => "NSEC".into(),
        Record::OPENPGPKEY(_)  => "OPENPGPKEY".into(),
        Record::PTR(_)         => "PTR".into(),
        Record::RRSIG(_)       => "RRSIG".into(),
        Record::SOA(_)         => "SOA".into(),
        Record::SRV(_)         => "SRV".into(),
        Record::SSHFP(_)       => "SSHFP".into(),
        Record::TLSA(_)        => "TLSA".into(),
        Record::TXT(_)         => "TXT".into(),
        Record::URI(_)         => "URI".into(),
        Record::Other { type_number, .. } => {
            match type_number {
                UnknownQtype::HeardOf(name, _)  => (*name).into(),
                UnknownQtype::UnheardOf(num)    => (*num).into(),
            }
        }
    }
}


/// Serialises a received DNS record as a JSON value.
///
/// Even though DNS doesn’t specify a character encoding, strings are still
/// converted from UTF-8, because JSON specifies UTF-8.
fn json_record_data(record: Record) -> JsonValue {
    match record {
        Record::A(a)                 => serde_json::json!({ "address": a.address.to_string() }),
        Record::AAAA(aaaa)           => serde_json::json!({ "address": aaaa.address.to_string() }),
        Record::CAA(caa)             => serde_json::json!({ "critical": caa.critical, "tag": lossy(&caa.tag), "value": lossy(&caa.value) }),
        Record::CNAME(cname)         => serde_json::json!({ "domain": cname.domain.to_string() }),
        Record::DNSKEY(dnskey)       => json_dnskey(&dnskey),
        Record::DS(ds)               => json_ds(&ds),
        Record::EUI48(eui48)         => serde_json::json!({ "identifier": eui48.formatted_address() }),
        Record::EUI64(eui64)         => serde_json::json!({ "identifier": eui64.formatted_address() }),
        Record::HINFO(hinfo)         => serde_json::json!({ "cpu": lossy(&hinfo.cpu), "os": lossy(&hinfo.os) }),
        Record::LOC(loc)             => json_loc(&loc),
        Record::MX(mx)               => serde_json::json!({ "preference": mx.preference, "exchange": mx.exchange.to_string() }),
        Record::NAPTR(naptr)         => json_naptr(&naptr),
        Record::NS(ns)               => serde_json::json!({ "nameserver": ns.nameserver.to_string() }),
        Record::NSEC(nsec)           => serde_json::json!({ "next_domain": nsec.next_domain.to_string(), "types": nsec.type_names() }),
        Record::OPENPGPKEY(opgp)     => serde_json::json!({ "key": opgp.base64_key() }),
        Record::PTR(ptr)             => serde_json::json!({ "cname": ptr.cname.to_string() }),
        Record::RRSIG(rrsig)         => json_rrsig(&rrsig),
        Record::SSHFP(sshfp)         => json_sshfp(&sshfp),
        Record::SOA(soa)             => json_soa(&soa),
        Record::SRV(srv)             => json_srv(&srv),
        Record::TLSA(tlsa)           => json_tlsa(&tlsa),
        Record::TXT(txt)             => serde_json::json!({ "messages": txt.messages.iter().map(|m| lossy(m)).collect::<Vec<_>>() }),
        Record::URI(uri)             => serde_json::json!({ "priority": uri.priority, "weight": uri.weight, "target": lossy(&uri.target) }),
        Record::Other { bytes, .. }  => serde_json::json!({ "bytes": bytes }),
    }
}

fn json_dnskey(dnskey: &dns::record::DNSKEY) -> JsonValue {
    let mut data = serde_json::json!({
        "flags": dnskey.flags,
        "protocol": dnskey.protocol,
        "algorithm": dnskey.algorithm,
    });
    insert_name(&mut data, "algorithm_name", dnskey.algorithm_name());
    data["public_key"] = dnskey.base64_public_key().into();
    data
}

fn json_ds(ds: &dns::record::DS) -> JsonValue {
    let mut data = serde_json::json!({
        "key_tag": ds.key_tag,
        "algorithm": ds.algorithm,
    });
    insert_name(&mut data, "algorithm_name", ds.algorithm_name());
    data["digest_type"] = ds.digest_type.into();
    insert_name(&mut data, "digest_type_name", ds.digest_type_name());
    data["digest"] = ds.hex_digest().into();
    data
}

fn json_loc(loc: &dns::record::LOC) -> JsonValue {
    serde_json::json!({
        "size": loc.size.to_string(),
        "precision": {
            "horizontal": loc.horizontal_precision.to_string(),
            "vertical": loc.vertical_precision.to_string(),
        },
        "point": {
            "latitude": loc.latitude.as_ref().map(ToString::to_string),
            "longitude": loc.longitude.as_ref().map(ToString::to_string),
            "altitude": loc.altitude.to_string(),
        },
    })
}

fn json_naptr(naptr: &dns::record::NAPTR) -> JsonValue {
    serde_json::json!({
        "order": naptr.order,
        "preference": naptr.preference,
        "flags": lossy(&naptr.flags),
        "service": lossy(&naptr.service),
        "regex": lossy(&naptr.regex),
        "replacement": naptr.replacement.to_string(),
    })
}

fn json_rrsig(rrsig: &dns::record::RRSIG) -> JsonValue {
    let mut data = serde_json::json!({
        "type_covered": rrsig.type_covered,
    });
    insert_name(&mut data, "type_covered_name", rrsig.type_covered_name());
    data["algorithm"] = rrsig.algorithm.into();
    insert_name(&mut data, "algorithm_name", rrsig.algorithm_name());
    data["labels"] = rrsig.labels.into();
    data["original_ttl"] = rrsig.original_ttl.into();
    data["signature_expiration"] = rrsig.signature_expiration.into();
    data["signature_inception"] = rrsig.signature_inception.into();
    data["key_tag"] = rrsig.key_tag.into();
    data["signer_name"] = rrsig.signer_name.to_string().into();
    data["signature"] = rrsig.base64_signature().into();
    data
}

fn json_sshfp(sshfp: &dns::record::SSHFP) -> JsonValue {
    serde_json::json!({
        "algorithm": sshfp.algorithm,
        "fingerprint_type": sshfp.fingerprint_type,
        "fingerprint": sshfp.hex_fingerprint(),
    })
}

fn json_soa(soa: &dns::record::SOA) -> JsonValue {
    serde_json::json!({
        "mname": soa.mname.to_string(),
        "rname": soa.rname.to_string(),
        "serial": soa.serial,
        "refresh": soa.refresh_interval,
        "retry": soa.retry_interval,
        "expire": soa.expire_limit,
        "minimum": soa.minimum_ttl,
    })
}

fn json_srv(srv: &dns::record::SRV) -> JsonValue {
    serde_json::json!({
        "priority": srv.priority,
        "weight": srv.weight,
        "port": srv.port,
        "target": srv.target.to_string(),
    })
}

fn json_tlsa(tlsa: &dns::record::TLSA) -> JsonValue {
    serde_json::json!({
        "certificate_usage": tlsa.certificate_usage,
        "selector": tlsa.selector,
        "matching_type": tlsa.matching_type,
        "certificate_data": tlsa.hex_certificate_data(),
    })
}

/// Adds a human-readable name to a JSON object, when there is one.
fn insert_name(object: &mut JsonValue, key: &str, name: Option<&str>) {
    if let Some(name) = name {
        object[key] = name.into();
    }
}

/// Bytes as a string, with anything that is not UTF-8 replaced.
fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}


/// A wrapper around displaying characters that escapes quotes and
/// backslashes, and writes control and upper-bit bytes as their number rather
/// than their character. This is needed because even though such characters
/// are not allowed in domain names, packets can contain anything, and we need
/// a way to display the response, whatever it is.
struct Ascii<'a>(&'a [u8]);

impl fmt::Display for Ascii<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;

        for byte in self.0.iter().copied() {
            write_escaped(f, byte)?;
        }

        f.write_str("\"")
    }
}

/// Writes one byte for `Ascii`: printable ASCII as itself, with quotes and
/// backslashes escaped, and anything else as a backslash and its number.
fn write_escaped(f: &mut fmt::Formatter<'_>, byte: u8) -> fmt::Result {
    match byte {
        b'"'        => f.write_str("\\\""),
        b'\\'       => f.write_str("\\\\"),
        32 ..= 127  => write!(f, "{}", char::from(byte)),
        _           => write!(f, "\\{byte}"),
    }
}


/// Returns the “phase” of operation where an error occurred. This gets shown
/// to the user so they can debug what went wrong.
fn erroneous_phase(error: &TransportError) -> &'static str {
    match error {
        TransportError::WireError(_)             |
        TransportError::MismatchedResponse(_)    => "protocol",
        TransportError::TruncatedResponse        |
        TransportError::NetworkError(_)          |
        TransportError::Timeout(_)               => "network",
        TransportError::InvalidNameserver(_)     => "options",
        #[cfg(any(feature = "with_tls", feature = "with_https"))]
        TransportError::TlsError(_)              |
        TransportError::TlsHandshakeError(_)     => "tls",
        #[cfg(feature = "with_https")]
        TransportError::HttpError(_)             |
        TransportError::WrongHttpStatus(_,_)     |
        TransportError::MalformedHttp(_)         => "http",
    }
}

/// Formats an error into its human-readable message.
fn error_message(error: TransportError) -> String {
    match error {
        TransportError::WireError(e)             => wire_error_message(e),
        TransportError::TruncatedResponse        => "Truncated response".into(),
        TransportError::NetworkError(e)          => e.to_string(),
        TransportError::Timeout(after)           => format!("Timed out after {after:?} waiting for a response"),
        TransportError::MismatchedResponse(m)    => m.to_string(),
        TransportError::InvalidNameserver(why)   => why,
        #[cfg(any(feature = "with_tls", feature = "with_https"))]
        TransportError::TlsError(e)              => e.to_string(),
        #[cfg(any(feature = "with_tls", feature = "with_https"))]
        TransportError::TlsHandshakeError(e)     => e.to_string(),
        #[cfg(feature = "with_https")]
        TransportError::HttpError(e)             => e.to_string(),
        #[cfg(feature = "with_https")]
        TransportError::WrongHttpStatus(t,r)     => http_status_message(t, r),
        #[cfg(feature = "with_https")]
        TransportError::MalformedHttp(why)       => why,
    }
}

/// The message for an HTTP status other than 200, with its reason phrase if
/// the server sent one. HTTP/2 has no reason phrases, and an HTTP/1.1
/// server can send an empty one.
#[cfg(feature = "with_https")]
fn http_status_message(status: u16, reason: Option<String>) -> String {
    match reason.filter(|reason| ! reason.is_empty()) {
        Some(reason) => format!("Nameserver returned HTTP {status} ({reason})"),
        None         => format!("Nameserver returned HTTP {status}"),
    }
}

/// Formats a wire error into its human-readable message, describing what was
/// wrong with the packet we received.
fn wire_error_message(error: WireError) -> String {
    match error {
        WireError::IO => {
            "Malformed packet: insufficient data".into()
        }
        WireError::WrongRecordLength { stated_length, mandated_length: MandatedLength::Exactly(len) } => {
            format!("Malformed packet: record length should be {len}, got {stated_length}" )
        }
        WireError::WrongRecordLength { stated_length, mandated_length: MandatedLength::AtLeast(len) } => {
            format!("Malformed packet: record length should be at least {len}, got {stated_length}" )
        }
        WireError::WrongLabelLength { stated_length, length_after_labels } => {
            format!("Malformed packet: length {stated_length} was specified, but read {length_after_labels} bytes")
        }
        WireError::TooMuchRecursion(indices) => {
            format!("Malformed packet: too much recursion: {indices:?}")
        }
        WireError::OutOfBounds(index) => {
            format!("Malformed packet: out of bounds ({index})")
        }
        WireError::WrongVersion { stated_version, maximum_supported_version } => {
            format!("Malformed packet: record specifies version {stated_version}, expected up to {maximum_supported_version}")
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use dns::record::{A, AAAA, CAA, CNAME, DNSKEY, DS, EUI48, EUI64, HINFO,
                      MX, NAPTR, NS, NSEC, OPENPGPKEY, PTR, RRSIG, SSHFP,
                      SOA, SRV, TLSA, TXT, URI};
    use dns::Labels;

    fn default_flags() -> Flags {
        Flags {
            response: false,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            error_code: None,
        }
    }

    // ============ errors ============

    #[test]
    fn wire_error_messages() {
        let cases = [
            (WireError::IO, "Malformed packet: insufficient data"),
            (WireError::WrongRecordLength { stated_length: 3, mandated_length: MandatedLength::Exactly(4) },
             "Malformed packet: record length should be 4, got 3"),
            (WireError::WrongRecordLength { stated_length: 3, mandated_length: MandatedLength::AtLeast(5) },
             "Malformed packet: record length should be at least 5, got 3"),
            (WireError::WrongLabelLength { stated_length: 9, length_after_labels: 11 },
             "Malformed packet: length 9 was specified, but read 11 bytes"),
            (WireError::TooMuchRecursion(vec![ 12, 12 ].into_boxed_slice()),
             "Malformed packet: too much recursion: [12, 12]"),
            (WireError::OutOfBounds(700), "Malformed packet: out of bounds (700)"),
            (WireError::WrongVersion { stated_version: 1, maximum_supported_version: 0 },
             "Malformed packet: record specifies version 1, expected up to 0"),
        ];

        for (error, message) in cases {
            let error = TransportError::WireError(error);
            assert_eq!(erroneous_phase(&error), "protocol");
            assert_eq!(error_message(error), message);
        }
    }

    #[test]
    fn transport_error_phases_and_messages() {
        #[allow(unused_mut)]
        let mut cases = vec![
            (TransportError::TruncatedResponse, "network", "Truncated response".to_owned()),
            (TransportError::NetworkError(std::io::ErrorKind::ConnectionRefused.into()), "network", "connection refused".to_owned()),
            (TransportError::Timeout(Duration::from_millis(1500)), "network", "Timed out after 1.5s waiting for a response".to_owned()),
            (TransportError::MismatchedResponse(dns::Mismatch::NotAResponse), "protocol", "Received a query, not a response".to_owned()),
            (TransportError::InvalidNameserver("Invalid nameserver \":53\": it has no host".into()), "options", "Invalid nameserver \":53\": it has no host".to_owned()),
        ];

        #[cfg(feature = "with_https")]
        cases.extend([
            (TransportError::WrongHttpStatus(404, Some("Not Found".into())), "http", "Nameserver returned HTTP 404 (Not Found)".to_owned()),
            // HTTP/2 has no reason phrases, and HTTP/1.1 can send an empty one.
            (TransportError::WrongHttpStatus(415, None), "http", "Nameserver returned HTTP 415".to_owned()),
            (TransportError::WrongHttpStatus(500, Some(String::new())), "http", "Nameserver returned HTTP 500".to_owned()),
            (TransportError::MalformedHttp("The response has no Content-Length".into()), "http", "The response has no Content-Length".to_owned()),
        ]);

        for (error, phase, message) in cases {
            assert_eq!(erroneous_phase(&error), phase);
            assert_eq!(error_message(error), message);
        }
    }

    #[test]
    fn status_lines() {
        let cases = [
            (ErrorCode::FormatError, "Format Error"),
            (ErrorCode::ServerFailure, "Server Failure"),
            (ErrorCode::NXDomain, "NXDomain"),
            (ErrorCode::NotImplemented, "Not Implemented"),
            (ErrorCode::QueryRefused, "Query Refused"),
            (ErrorCode::BadVersion, "Bad Version"),
            (ErrorCode::Private(3841), "Private Reason (3841)"),
            (ErrorCode::Other(11), "Other Failure (11)"),
        ];

        for (code, description) in cases {
            assert_eq!(error_code_description(code), description);
        }
    }

    /// An OPT record only turns up in the answer section of a malformed
    /// response, but short mode still summarises it.
    #[test]
    fn short_summary_of_a_pseudo_record() {
        let opt = OPT { udp_payload_size: 1232, higher_bits: 0, edns0_version: 0, flags: 0x8000, data: vec![ 1 ] };
        let answer = Answer::Pseudo { qname: Labels::root(), opt };
        assert_eq!(answer_summary(TextFormat { format_durations: true }, answer), "1232 0 0 32768 [1]");
    }

    #[test]
    fn json_names_of_every_record_type() {
        let cases = [
            (RecordType::A, "A"), (RecordType::AAAA, "AAAA"), (RecordType::CAA, "CAA"),
            (RecordType::CNAME, "CNAME"), (RecordType::DNSKEY, "DNSKEY"), (RecordType::DS, "DS"),
            (RecordType::EUI48, "EUI48"), (RecordType::EUI64, "EUI64"), (RecordType::HINFO, "HINFO"),
            (RecordType::LOC, "LOC"), (RecordType::MX, "MX"), (RecordType::NAPTR, "NAPTR"),
            (RecordType::NS, "NS"), (RecordType::NSEC, "NSEC"), (RecordType::OPENPGPKEY, "OPENPGPKEY"),
            (RecordType::PTR, "PTR"), (RecordType::RRSIG, "RRSIG"), (RecordType::SOA, "SOA"),
            (RecordType::SRV, "SRV"), (RecordType::SSHFP, "SSHFP"), (RecordType::TLSA, "TLSA"),
            (RecordType::TXT, "TXT"), (RecordType::URI, "URI"),
        ];

        for (record_type, name) in cases {
            assert_eq!(json_record_type_name(record_type), name);
            assert_eq!(RecordType::from(record_type.type_number()), record_type);
        }
    }

    #[test]
    fn escape_quotes() {
        assert_eq!(Ascii(b"Mallard \"The Duck\" Fillmore").to_string(),
                   "\"Mallard \\\"The Duck\\\" Fillmore\"");
    }

    #[test]
    fn escape_backslashes() {
        assert_eq!(Ascii(b"\\").to_string(),
                   "\"\\\\\"");
    }

    #[test]
    fn escape_lows() {
        assert_eq!(Ascii(b"\n\r\t").to_string(),
                   "\"\\10\\13\\9\"");
    }

    #[test]
    fn escape_highs() {
        assert_eq!(Ascii("pâté".as_bytes()).to_string(),
                   "\"p\\195\\162t\\195\\169\"");
    }

    // ============ json_flags tests ============

    #[test]
    fn json_flags_default() {
        let j = json_flags(default_flags());
        assert_eq!(j["qr"], false);
        assert_eq!(j["opcode"], "QUERY");
        assert_eq!(j["aa"], false);
        assert_eq!(j["tc"], false);
        assert_eq!(j["rd"], false);
        assert_eq!(j["ra"], false);
        assert_eq!(j["ad"], false);
        assert_eq!(j["cd"], false);
        assert_eq!(j["rcode"], "NOERROR");
    }

    #[test]
    fn json_flags_qr() {
        let mut f = default_flags();
        f.response = true;
        assert_eq!(json_flags(f)["qr"], true);
    }

    #[test]
    fn json_flags_aa() {
        let mut f = default_flags();
        f.authoritative = true;
        assert_eq!(json_flags(f)["aa"], true);
    }

    #[test]
    fn json_flags_tc_rd_ra() {
        let mut f = default_flags();
        f.truncated = true;
        f.recursion_desired = true;
        f.recursion_available = true;
        let j = json_flags(f);
        assert_eq!(j["tc"], true);
        assert_eq!(j["rd"], true);
        assert_eq!(j["ra"], true);
    }

    #[test]
    fn json_flags_ad_cd() {
        let mut f = default_flags();
        f.authentic_data = true;
        f.checking_disabled = true;
        let j = json_flags(f);
        assert_eq!(j["ad"], true);
        assert_eq!(j["cd"], true);
    }

    #[test]
    fn json_flags_opcode_other() {
        let mut f = default_flags();
        f.opcode = Opcode::Other(4);
        assert_eq!(json_flags(f)["opcode"], 4);
    }

    #[test]
    fn json_flags_rcode_nxdomain() {
        let mut f = default_flags();
        f.error_code = Some(ErrorCode::NXDomain);
        assert_eq!(json_flags(f)["rcode"], "NXDOMAIN");
    }

    #[test]
    fn json_flags_rcode_servfail() {
        let mut f = default_flags();
        f.error_code = Some(ErrorCode::ServerFailure);
        assert_eq!(json_flags(f)["rcode"], "SERVFAIL");
    }

    #[test]
    fn json_flags_rcode_named() {
        let cases: Vec<(ErrorCode, &str)> = vec![
            (ErrorCode::FormatError, "FORMERR"),
            (ErrorCode::NotImplemented, "NOTIMP"),
            (ErrorCode::QueryRefused, "REFUSED"),
            (ErrorCode::BadVersion, "BADVERS"),
        ];
        for (code, expected) in cases {
            let mut f = default_flags();
            f.error_code = Some(code);
            assert_eq!(json_flags(f)["rcode"], expected);
        }
    }

    #[test]
    fn json_flags_rcode_other_and_private() {
        let mut f = default_flags();
        f.error_code = Some(ErrorCode::Other(11));
        assert_eq!(json_flags(f)["rcode"], 11);

        let mut f = default_flags();
        f.error_code = Some(ErrorCode::Private(3841));
        assert_eq!(json_flags(f)["rcode"], 3841);
    }

    // ============ json_class tests ============

    #[test]
    fn json_class_in() {
        assert_eq!(json_class(QClass::IN), "IN");
    }

    #[test]
    fn json_class_ch() {
        assert_eq!(json_class(QClass::CH), "CH");
    }

    #[test]
    fn json_class_hs() {
        assert_eq!(json_class(QClass::HS), "HS");
    }

    #[test]
    fn json_class_other() {
        assert_eq!(json_class(QClass::Other(254)), 254);
    }

    // ============ json_record_type_name + json_record_name tests ============

    #[test]
    fn json_record_type_name_a() {
        assert_eq!(json_record_type_name(RecordType::A), "A");
    }

    #[test]
    fn json_record_type_name_aaaa() {
        assert_eq!(json_record_type_name(RecordType::AAAA), "AAAA");
    }

    #[test]
    fn json_record_type_name_heard_of() {
        assert_eq!(json_record_type_name(RecordType::Other(UnknownQtype::HeardOf("NSEC3", 50))), "NSEC3");
    }

    #[test]
    fn json_record_type_name_unheard_of() {
        assert_eq!(json_record_type_name(RecordType::Other(UnknownQtype::UnheardOf(9999))), 9999);
    }

    #[test]
    fn json_record_name_a() {
        let record = Record::A(A { address: Ipv4Addr::new(1, 2, 3, 4) });
        assert_eq!(json_record_name(&record), "A");
    }

    #[test]
    fn json_record_name_other() {
        let record = Record::Other {
            type_number: UnknownQtype::UnheardOf(9999),
            bytes: vec![],
        };
        assert_eq!(json_record_name(&record), 9999);
    }

    // ============ json_record_data tests ============

    #[test]
    fn json_record_data_a() {
        let j = json_record_data(Record::A(A { address: Ipv4Addr::new(192, 0, 2, 1) }));
        assert_eq!(j["address"], "192.0.2.1");
    }

    #[test]
    fn json_record_data_aaaa() {
        let j = json_record_data(Record::AAAA(AAAA {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        }));
        assert_eq!(j["address"], "2001:db8::1");
    }

    #[test]
    fn json_record_data_caa() {
        let j = json_record_data(Record::CAA(CAA {
            critical: true,
            tag: b"issue".to_vec().into_boxed_slice(),
            value: b"letsencrypt.org".to_vec().into_boxed_slice(),
        }));
        assert_eq!(j["critical"], true);
        assert_eq!(j["tag"], "issue");
        assert_eq!(j["value"], "letsencrypt.org");
    }

    #[test]
    fn json_record_data_cname() {
        let j = json_record_data(Record::CNAME(CNAME {
            domain: Labels::encode("www.example.com").unwrap(),
        }));
        assert_eq!(j["domain"], "www.example.com.");
    }

    #[test]
    fn json_record_data_dnskey() {
        let j = json_record_data(Record::DNSKEY(DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 8,
            public_key: vec![1, 2, 3],
        }));
        assert_eq!(j["flags"], 257);
        assert_eq!(j["protocol"], 3);
        assert_eq!(j["algorithm"], 8);
        assert_eq!(j["algorithm_name"], "RSASHA256");
        assert_eq!(j["public_key"], "AQID");
    }

    #[test]
    fn json_record_data_ds() {
        let j = json_record_data(Record::DS(DS {
            key_tag: 40714,
            algorithm: 13,
            digest_type: 2,
            digest: vec![0xAA, 0xBB],
        }));
        assert_eq!(j["key_tag"], 40714);
        assert_eq!(j["algorithm"], 13);
        assert_eq!(j["algorithm_name"], "ECDSAP256SHA256");
        assert_eq!(j["digest_type"], 2);
        assert_eq!(j["digest_type_name"], "SHA-256");
        assert_eq!(j["digest"], "aabb");
    }

    #[test]
    fn json_record_data_eui48() {
        let j = json_record_data(Record::EUI48(EUI48 {
            octets: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        }));
        assert_eq!(j["identifier"], "00-11-22-33-44-55");
    }

    #[test]
    fn json_record_data_eui64() {
        let j = json_record_data(Record::EUI64(EUI64 {
            octets: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        }));
        assert_eq!(j["identifier"], "00-11-22-33-44-55-66-77");
    }

    #[test]
    fn json_record_data_hinfo() {
        let j = json_record_data(Record::HINFO(HINFO {
            cpu: b"Intel".to_vec().into_boxed_slice(),
            os: b"Linux".to_vec().into_boxed_slice(),
        }));
        assert_eq!(j["cpu"], "Intel");
        assert_eq!(j["os"], "Linux");
    }

    #[test]
    fn json_record_data_mx() {
        let j = json_record_data(Record::MX(MX {
            preference: 10,
            exchange: Labels::encode("mail.example.com").unwrap(),
        }));
        assert_eq!(j["preference"], 10);
        assert_eq!(j["exchange"], "mail.example.com.");
    }

    #[test]
    fn json_record_data_naptr() {
        let j = json_record_data(Record::NAPTR(NAPTR {
            order: 100,
            preference: 10,
            flags: b"u".to_vec().into_boxed_slice(),
            service: b"E2U+sip".to_vec().into_boxed_slice(),
            regex: b"!^.*$!sip:info@example.com!".to_vec().into_boxed_slice(),
            replacement: Labels::encode(".").unwrap(),
        }));
        assert_eq!(j["order"], 100);
        // The text summary always had the preference; the JSON left it out.
        assert_eq!(j["preference"], 10);
        assert_eq!(j["flags"], "u");
        assert_eq!(j["service"], "E2U+sip");
        assert_eq!(j["regex"], "!^.*$!sip:info@example.com!");
        // The root, not the empty string. A NAPTR replacement of "." is RFC 3403
        // terminal — it means "stop here" — and rendering it as "" erased that.
        assert_eq!(j["replacement"], ".");
    }

    #[test]
    fn json_record_data_ns() {
        let j = json_record_data(Record::NS(NS {
            nameserver: Labels::encode("ns1.example.com").unwrap(),
        }));
        assert_eq!(j["nameserver"], "ns1.example.com.");
    }

    #[test]
    fn json_record_data_nsec() {
        let j = json_record_data(Record::NSEC(NSEC {
            next_domain: Labels::encode("beta.example.com").unwrap(),
            types: vec![1, 2],
        }));
        assert_eq!(j["next_domain"], "beta.example.com.");
        assert_eq!(j["types"][0], "A");
        assert_eq!(j["types"][1], "NS");
    }

    #[test]
    fn json_record_data_openpgpkey() {
        let j = json_record_data(Record::OPENPGPKEY(OPENPGPKEY {
            key: vec![1, 2, 3],
        }));
        assert_eq!(j["key"], "AQID");
    }

    #[test]
    fn json_record_data_ptr() {
        let j = json_record_data(Record::PTR(PTR {
            cname: Labels::encode("host.example.com").unwrap(),
        }));
        assert_eq!(j["cname"], "host.example.com.");
    }

    #[test]
    fn json_record_data_rrsig() {
        let j = json_record_data(Record::RRSIG(RRSIG {
            type_covered: 1,
            algorithm: 13,
            labels: 2,
            original_ttl: 3600,
            signature_expiration: 1_000_000,
            signature_inception: 999_000,
            key_tag: 2371,
            signer_name: Labels::encode("example.com").unwrap(),
            signature: vec![0xAA, 0xBB, 0xCC, 0xDD],
        }));
        assert_eq!(j["type_covered"], 1);
        assert_eq!(j["type_covered_name"], "A");
        assert_eq!(j["algorithm"], 13);
        assert_eq!(j["algorithm_name"], "ECDSAP256SHA256");
        assert_eq!(j["labels"], 2);
        assert_eq!(j["original_ttl"], 3600);
        assert_eq!(j["signature_expiration"], 1_000_000);
        assert_eq!(j["signature_inception"], 999_000);
        assert_eq!(j["key_tag"], 2371);
        assert_eq!(j["signer_name"], "example.com.");
        assert_eq!(j["signature"], "qrvM3Q==");
    }

    #[test]
    fn json_record_data_sshfp() {
        let j = json_record_data(Record::SSHFP(SSHFP {
            algorithm: 1,
            fingerprint_type: 1,
            fingerprint: vec![0xAA, 0xBB],
        }));
        assert_eq!(j["algorithm"], 1);
        assert_eq!(j["fingerprint_type"], 1);
        assert_eq!(j["fingerprint"], "aabb");
    }

    #[test]
    fn json_record_data_soa() {
        let j = json_record_data(Record::SOA(SOA {
            mname: Labels::encode("ns1.example.com").unwrap(),
            rname: Labels::encode("admin.example.com").unwrap(),
            serial: 2_021_010_100,
            refresh_interval: 3600,
            retry_interval: 900,
            expire_limit: 604_800,
            minimum_ttl: 86400,
        }));
        assert_eq!(j["mname"], "ns1.example.com.");
        assert_eq!(j["rname"], "admin.example.com.");
        assert_eq!(j["serial"], 2_021_010_100_u32);
        assert_eq!(j["refresh"], 3600);
        assert_eq!(j["retry"], 900);
        assert_eq!(j["expire"], 604_800);
        assert_eq!(j["minimum"], 86400);
    }

    #[test]
    fn json_record_data_srv() {
        let j = json_record_data(Record::SRV(SRV {
            priority: 10,
            weight: 60,
            port: 5060,
            target: Labels::encode("sip.example.com").unwrap(),
        }));
        assert_eq!(j["priority"], 10);
        assert_eq!(j["weight"], 60);
        assert_eq!(j["port"], 5060);
        assert_eq!(j["target"], "sip.example.com.");
    }

    #[test]
    fn json_record_data_tlsa() {
        let j = json_record_data(Record::TLSA(TLSA {
            certificate_usage: 3,
            selector: 1,
            matching_type: 1,
            certificate_data: vec![0xAA, 0xBB],
        }));
        assert_eq!(j["certificate_usage"], 3);
        assert_eq!(j["selector"], 1);
        assert_eq!(j["matching_type"], 1);
        assert_eq!(j["certificate_data"], "aabb");
    }

    #[test]
    fn json_record_data_txt() {
        let j = json_record_data(Record::TXT(TXT {
            messages: vec![b"v=spf1 include:example.com ~all".to_vec().into_boxed_slice()],
        }));
        assert_eq!(j["messages"][0], "v=spf1 include:example.com ~all");
    }

    #[test]
    fn json_record_data_uri() {
        let j = json_record_data(Record::URI(URI {
            priority: 10,
            weight: 1,
            target: b"https://example.com".to_vec().into_boxed_slice(),
        }));
        assert_eq!(j["priority"], 10);
        assert_eq!(j["weight"], 1);
        assert_eq!(j["target"], "https://example.com");
    }

    #[test]
    fn json_record_data_other() {
        let j = json_record_data(Record::Other {
            type_number: UnknownQtype::UnheardOf(9999),
            bytes: vec![1, 2, 3],
        });
        assert_eq!(j["bytes"][0], 1);
        assert_eq!(j["bytes"][1], 2);
        assert_eq!(j["bytes"][2], 3);
    }

    // ============ json_queries tests ============

    #[test]
    fn json_queries_empty() {
        let j = json_queries(&[]);
        assert_eq!(j.as_array().map_or(0, Vec::len), 0);
    }

    #[test]
    fn json_queries_single() {
        let j = json_queries(&[
            Query {
                qname: Labels::encode("example.com").unwrap(),
                qclass: QClass::IN,
                qtype: RecordType::A,
            },
        ]);
        assert_eq!(j.as_array().map_or(0, Vec::len), 1);
        assert_eq!(j[0]["name"], "example.com.");
        assert_eq!(j[0]["class"], "IN");
        assert_eq!(j[0]["type"], "A");
    }

    #[test]
    fn json_queries_multiple() {
        let j = json_queries(&[
            Query {
                qname: Labels::encode("example.com").unwrap(),
                qclass: QClass::IN,
                qtype: RecordType::A,
            },
            Query {
                qname: Labels::encode("example.com").unwrap(),
                qclass: QClass::IN,
                qtype: RecordType::AAAA,
            },
        ]);
        assert_eq!(j.as_array().map_or(0, Vec::len), 2);
        assert_eq!(j[0]["type"], "A");
        assert_eq!(j[1]["type"], "AAAA");
    }

    // ============ json_answers tests ============

    #[test]
    fn json_answers_standard() {
        let j = json_answers(vec![
            Answer::Standard {
                qname: Labels::encode("example.com").unwrap(),
                qclass: QClass::IN,
                ttl: 300,
                record: Record::A(A { address: Ipv4Addr::new(93, 184, 216, 34) }),
            },
        ]);
        assert_eq!(j.as_array().map_or(0, Vec::len), 1);
        assert_eq!(j[0]["name"], "example.com.");
        assert_eq!(j[0]["class"], "IN");
        assert_eq!(j[0]["ttl"], 300);
        assert_eq!(j[0]["type"], "A");
        assert_eq!(j[0]["data"]["address"], "93.184.216.34");
    }

    #[test]
    fn json_answers_pseudo() {
        let j = json_answers(vec![
            Answer::Pseudo {
                qname: Labels::encode(".").unwrap(),
                opt: OPT {
                    udp_payload_size: 4096,
                    higher_bits: 0,
                    edns0_version: 0,
                    flags: 0,
                    data: vec![],
                },
            },
        ]);
        assert_eq!(j.as_array().map_or(0, Vec::len), 1);
        assert_eq!(j[0]["type"], "OPT");
        assert_eq!(j[0]["data"]["version"], 0);
        assert_eq!(j[0]["data"]["dnssec_ok"], false);
    }

    /// The text showed the payload size and the DO bit; the JSON left out
    /// everything but the version and the data.
    #[test]
    fn json_answers_pseudo_fields() {
        let opt = OPT { udp_payload_size: 1232, higher_bits: 1, edns0_version: 0, flags: 0x8000, data: vec![ 0, 15 ] };
        let j = json_answers(vec![ Answer::Pseudo { qname: Labels::root(), opt } ]);
        assert_eq!(j[0]["data"], serde_json::json!({
            "udp_payload_size": 1232, "extended_rcode_bits": 1, "version": 0, "flags": 32768, "dnssec_ok": true, "data": [ 0, 15 ],
        }));
    }

    /// Names escape themselves, so quoting one must not escape it again, as
    /// formatting it with `{:?}` did: a backslash became two.
    #[test]
    fn names_are_quoted_as_they_are_escaped() {
        let name = Labels::encode("xn--bcher-kva.example").unwrap();
        assert_eq!(quoted(&name), "\"xn--bcher-kva.example.\"");
        assert_eq!(quoted(&Labels::root()), "\".\"");

        let summary = |fixture: &str| {
            let response = Response::from_bytes(&test_support::fixtures::response(fixture)).unwrap();
            let record = response.answers.into_iter().find_map(|a| if let Answer::Standard { record, .. } = a { Some(record) } else { None }).unwrap();
            TextFormat { format_durations: false }.record_payload_summary(record)
        };
        assert_eq!(summary("nsec-ietf").split(' ').next(), Some(r#""\000.ietf.org.""#));
    }

    #[test]
    fn json_answers_empty() {
        let j = json_answers(vec![]);
        assert_eq!(j.as_array().map_or(0, Vec::len), 0);
    }

    // ============ format_duration_hms tests ============

    #[test]
    fn duration_zero() {
        assert_eq!(format_duration_hms(0), "0s");
    }

    #[test]
    fn duration_seconds() {
        assert_eq!(format_duration_hms(42), "42s");
    }

    #[test]
    fn duration_59_seconds() {
        assert_eq!(format_duration_hms(59), "59s");
    }

    #[test]
    fn duration_minutes_seconds() {
        assert_eq!(format_duration_hms(90), "1m30s");
    }

    #[test]
    fn duration_59_minutes() {
        assert_eq!(format_duration_hms(3599), "59m59s");
    }

    #[test]
    fn duration_hours() {
        assert_eq!(format_duration_hms(3661), "1h01m01s");
    }

    #[test]
    fn duration_days() {
        assert_eq!(format_duration_hms(90061), "1d1h01m01s");
    }

    // ============ TextFormat::record_payload_summary tests ============

    #[test]
    fn summary_a() {
        let tf = TextFormat { format_durations: false };
        let r = Record::A(A { address: Ipv4Addr::new(192, 0, 2, 1) });
        assert_eq!(tf.record_payload_summary(r), "192.0.2.1");
    }

    #[test]
    fn summary_aaaa() {
        let tf = TextFormat { format_durations: false };
        let r = Record::AAAA(AAAA {
            address: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        });
        assert_eq!(tf.record_payload_summary(r), "2001:db8::1");
    }

    #[test]
    fn summary_cname() {
        let tf = TextFormat { format_durations: false };
        let r = Record::CNAME(CNAME {
            domain: Labels::encode("www.example.com").unwrap(),
        });
        assert_eq!(tf.record_payload_summary(r), "\"www.example.com.\"");
    }

    #[test]
    fn summary_mx() {
        let tf = TextFormat { format_durations: false };
        let r = Record::MX(MX {
            preference: 10,
            exchange: Labels::encode("mail.example.com").unwrap(),
        });
        assert_eq!(tf.record_payload_summary(r), "10 \"mail.example.com.\"");
    }

    #[test]
    fn summary_ns() {
        let tf = TextFormat { format_durations: false };
        let r = Record::NS(NS {
            nameserver: Labels::encode("ns1.example.com").unwrap(),
        });
        assert_eq!(tf.record_payload_summary(r), "\"ns1.example.com.\"");
    }

    #[test]
    fn summary_txt_single() {
        let tf = TextFormat { format_durations: false };
        let r = Record::TXT(TXT {
            messages: vec![b"hello world".to_vec().into_boxed_slice()],
        });
        assert_eq!(tf.record_payload_summary(r), "\"hello world\"");
    }

    #[test]
    fn summary_txt_multi() {
        let tf = TextFormat { format_durations: false };
        let r = Record::TXT(TXT {
            messages: vec![
                b"hello".to_vec().into_boxed_slice(),
                b"world".to_vec().into_boxed_slice(),
            ],
        });
        assert_eq!(tf.record_payload_summary(r), "\"hello\", \"world\"");
    }

    #[test]
    fn summary_caa_critical() {
        let tf = TextFormat { format_durations: false };
        let r = Record::CAA(CAA {
            critical: true,
            tag: b"issue".to_vec().into_boxed_slice(),
            value: b"letsencrypt.org".to_vec().into_boxed_slice(),
        });
        assert_eq!(tf.record_payload_summary(r),
                   "\"issue\" \"letsencrypt.org\" (critical)");
    }

    #[test]
    fn summary_caa_noncritical() {
        let tf = TextFormat { format_durations: false };
        let r = Record::CAA(CAA {
            critical: false,
            tag: b"issue".to_vec().into_boxed_slice(),
            value: b"letsencrypt.org".to_vec().into_boxed_slice(),
        });
        assert_eq!(tf.record_payload_summary(r),
                   "\"issue\" \"letsencrypt.org\" (non-critical)");
    }

    #[test]
    fn summary_soa_raw() {
        let tf = TextFormat { format_durations: false };
        let r = Record::SOA(SOA {
            mname: Labels::encode("ns1.example.com").unwrap(),
            rname: Labels::encode("admin.example.com").unwrap(),
            serial: 2_021_010_100,
            refresh_interval: 3600,
            retry_interval: 900,
            expire_limit: 604_800,
            minimum_ttl: 86400,
        });
        assert_eq!(tf.record_payload_summary(r),
                   "\"ns1.example.com.\" \"admin.example.com.\" 2021010100 3600 900 604800 86400");
    }

    #[test]
    fn summary_soa_formatted() {
        let tf = TextFormat { format_durations: true };
        let r = Record::SOA(SOA {
            mname: Labels::encode("ns1.example.com").unwrap(),
            rname: Labels::encode("admin.example.com").unwrap(),
            serial: 2_021_010_100,
            refresh_interval: 3600,
            retry_interval: 900,
            expire_limit: 604_800,
            minimum_ttl: 86400,
        });
        assert_eq!(tf.record_payload_summary(r),
                   "\"ns1.example.com.\" \"admin.example.com.\" 2021010100 1h00m00s 15m00s 7d0h00m00s 1d0h00m00s");
    }

    #[test]
    fn summary_other() {
        let tf = TextFormat { format_durations: false };
        let r = Record::Other {
            type_number: UnknownQtype::UnheardOf(9999),
            bytes: vec![1, 2, 3],
        };
        assert_eq!(tf.record_payload_summary(r), "[1, 2, 3]");
    }
}
