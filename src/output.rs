//! Text and JSON output.

use std::fmt;
use std::time::Duration;
use std::env;

use dns::{Response, Query, Answer, QClass, ErrorCode, WireError, MandatedLength};
use dns::record::{Record, RecordType, UnknownQtype, OPT};
use dns_transport::Error as TransportError;
use json::{object, JsonValue};

use crate::colours::Colours;
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
        self == Self::Always || (atty::is(atty::Stream::Stdout) && env::var("NO_COLOR").is_err() && self != Self::Never)
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
    pub fn print(self, responses: Vec<Response>, duration: Option<Duration>) -> bool {
        match self {
            Self::Short(tf) => {
                let all_answers = responses.into_iter().flat_map(|r| r.answers).collect::<Vec<_>>();

                if all_answers.is_empty() {
                    eprintln!("No results");
                    return false;
                }

                for answer in all_answers {
                    match answer {
                        Answer::Standard { record, .. } => {
                            println!("{}", tf.record_payload_summary(record))
                        }
                        Answer::Pseudo { opt, .. } => {
                            println!("{}", tf.pseudo_record_payload_summary(opt))
                        }
                    }

                }
            }
            Self::JSON => {
                let mut rs = Vec::new();

                for response in responses {
                    let json = object! {
                        "queries": json_queries(response.queries),
                        "answers": json_answers(response.answers),
                        "authorities": json_answers(response.authorities),
                        "additionals": json_answers(response.additionals),
                    };

                    rs.push(json);
                }

                if let Some(duration) = duration {
                    let object = object! {
                        "responses": rs,
                        "duration": {
                            "secs": duration.as_secs(),
                            "millis": duration.subsec_millis(),
                        },
                    };

                    println!("{}", object);
                }
                else {
                    let object = object! {
                        "responses": rs,
                    };

                    println!("{}", object);
                }
            }
            Self::Text(uc, tf) => {
                let mut table = Table::new(uc.palette(), tf);

                for response in responses {
                    if let Some(rcode) = response.flags.error_code {
                        print_error_code(rcode);
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

                table.print(duration);
            }
        }

        true
    }

    /// Print an error that’s occurred while sending or receiving DNS packets
    /// to standard error.
    pub fn print_error(self, error: TransportError) {
        match self {
            Self::Short(..) | Self::Text(..) => {
                eprintln!("Error [{}]: {}", erroneous_phase(&error), error_message(error));
            }

            Self::JSON => {
                let object = object! {
                    "error": true,
                    "error_phase": erroneous_phase(&error),
                    "error_message": error_message(error),
                };

                eprintln!("{}", object);
            }
        }
    }
}

impl TextFormat {

    /// Formats a summary of a record in a received DNS response. Each record
    /// type contains wildly different data, so the format of the summary
    /// depends on what record it’s for.
    pub fn record_payload_summary(self, record: Record) -> String {
        match record {
            Record::A(a) => {
                format!("{}", a.address)
            }
            Record::AAAA(aaaa) => {
                format!("{}", aaaa.address)
            }
            Record::CAA(caa) => {
                if caa.critical {
                    format!("{} {} (critical)", Ascii(&caa.tag), Ascii(&caa.value))
                }
                else {
                    format!("{} {} (non-critical)", Ascii(&caa.tag), Ascii(&caa.value))
                }
            }
            Record::CNAME(cname) => {
                format!("{:?}", cname.domain.to_string())
            }
            Record::EUI48(eui48) => {
                format!("{:?}", eui48.formatted_address())
            }
            Record::EUI64(eui64) => {
                format!("{:?}", eui64.formatted_address())
            }
            Record::HINFO(hinfo) => {
                format!("{} {}", Ascii(&hinfo.cpu), Ascii(&hinfo.os))
            }
            Record::LOC(loc) => {
                format!("{} ({}, {}) ({}, {}, {})",
                    loc.size,
                    loc.horizontal_precision,
                    loc.vertical_precision,
                    loc.latitude .map_or_else(|| "Out of range".into(), |e| e.to_string()),
                    loc.longitude.map_or_else(|| "Out of range".into(), |e| e.to_string()),
                    loc.altitude,
                )
            }
            Record::MX(mx) => {
                format!("{} {:?}", mx.preference, mx.exchange.to_string())
            }
            Record::NAPTR(naptr) => {
                format!("{} {} {} {} {} {:?}",
                    naptr.order,
                    naptr.preference,
                    Ascii(&naptr.flags),
                    Ascii(&naptr.service),
                    Ascii(&naptr.regex),
                    naptr.replacement.to_string(),
                )
            }
            Record::NS(ns) => {
                format!("{:?}", ns.nameserver.to_string())
            }
            Record::OPENPGPKEY(opgp) => {
                format!("{:?}", opgp.base64_key())
            }
            Record::PTR(ptr) => {
                format!("{:?}", ptr.cname.to_string())
            }
            Record::SSHFP(sshfp) => {
                format!("{} {} {}",
                    sshfp.algorithm,
                    sshfp.fingerprint_type,
                    sshfp.hex_fingerprint(),
                )
            }
            Record::SOA(soa) => {
                format!("{:?} {:?} {} {} {} {} {}",
                    soa.mname.to_string(),
                    soa.rname.to_string(),
                    soa.serial,
                    self.format_duration(soa.refresh_interval),
                    self.format_duration(soa.retry_interval),
                    self.format_duration(soa.expire_limit),
                    self.format_duration(soa.minimum_ttl),
                )
            }
            Record::SRV(srv) => {
                format!("{} {} {:?}:{}", srv.priority, srv.weight, srv.target.to_string(), srv.port)
            }
            Record::TLSA(tlsa) => {
                format!("{} {} {} {:?}",
                    tlsa.certificate_usage,
                    tlsa.selector,
                    tlsa.matching_type,
                    tlsa.hex_certificate_data(),
                )
            }
            Record::TXT(txt) => {
                let messages = txt.messages.iter().map(|t| Ascii(t).to_string()).collect::<Vec<_>>();
                messages.join(", ")
            }
            Record::URI(uri) => {
                format!("{} {} {}", uri.priority, uri.weight, Ascii(&uri.target))
            }
            Record::Other { bytes, .. } => {
                format!("{:?}", bytes)
            }
        }
    }

    /// Formats a summary of an OPT pseudo-record. Pseudo-records have a different
    /// structure than standard ones.
    pub fn pseudo_record_payload_summary(self, opt: OPT) -> String {
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
            format!("{}", seconds)
        }
    }
}

/// Formats a duration as days, hours, minutes, and seconds, skipping leading
/// zero units.
fn format_duration_hms(seconds: u32) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
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

/// Serialises multiple DNS queries as a JSON value.
fn json_queries(queries: Vec<Query>) -> JsonValue {
    let queries = queries.iter().map(|q| {
        object! {
            "name": q.qname.to_string(),
            "class": json_class(q.qclass),
            "type": json_record_type_name(q.qtype),
        }
    }).collect::<Vec<_>>();

    queries.into()
}

/// Serialises multiple received DNS answers as a JSON value.
fn json_answers(answers: Vec<Answer>) -> JsonValue {
    let answers = answers.into_iter().map(|a| {
        match a {
            Answer::Standard { qname, qclass, ttl, record } => {
                object! {
                    "name": qname.to_string(),
                    "class": json_class(qclass),
                    "ttl": ttl,
                    "type": json_record_name(&record),
                    "data": json_record_data(record),
                }
            }
            Answer::Pseudo { qname, opt } => {
                object! {
                    "name": qname.to_string(),
                    "type": "OPT",
                    "data": {
                        "version": opt.edns0_version,
                        "data": opt.data,
                    },
                }
            }
        }
    }).collect::<Vec<_>>();

    answers.into()
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
        RecordType::EUI48       => "EUI48".into(),
        RecordType::EUI64       => "EUI64".into(),
        RecordType::HINFO       => "HINFO".into(),
        RecordType::LOC         => "LOC".into(),
        RecordType::MX          => "MX".into(),
        RecordType::NAPTR       => "NAPTR".into(),
        RecordType::NS          => "NS".into(),
        RecordType::OPENPGPKEY  => "OPENPGPKEY".into(),
        RecordType::PTR         => "PTR".into(),
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
        Record::EUI48(_)       => "EUI48".into(),
        Record::EUI64(_)       => "EUI64".into(),
        Record::HINFO(_)       => "HINFO".into(),
        Record::LOC(_)         => "LOC".into(),
        Record::MX(_)          => "MX".into(),
        Record::NAPTR(_)       => "NAPTR".into(),
        Record::NS(_)          => "NS".into(),
        Record::OPENPGPKEY(_)  => "OPENPGPKEY".into(),
        Record::PTR(_)         => "PTR".into(),
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

/// Even though DNS doesn’t specify a character encoding, strings are still
/// converted from UTF-8, because JSON specifies UTF-8.
fn json_record_data(record: Record) -> JsonValue {
    match record {
        Record::A(a) => {
            object! {
                "address": a.address.to_string(),
            }
        }
        Record::AAAA(aaaa) => {
            object! {
                "address": aaaa.address.to_string(),
            }
        }
        Record::CAA(caa) => {
            object! {
                "critical": caa.critical,
                "tag": String::from_utf8_lossy(&caa.tag).to_string(),
                "value": String::from_utf8_lossy(&caa.value).to_string(),
            }
        }
        Record::CNAME(cname) => {
            object! {
                "domain": cname.domain.to_string(),
            }
        }
        Record::EUI48(eui48) => {
            object! {
                "identifier": eui48.formatted_address(),
            }
        }
        Record::EUI64(eui64) => {
            object! {
                "identifier": eui64.formatted_address(),
            }
        }
        Record::HINFO(hinfo) => {
            object! {
                "cpu": String::from_utf8_lossy(&hinfo.cpu).to_string(),
                "os": String::from_utf8_lossy(&hinfo.os).to_string(),
            }
        }
        Record::LOC(loc) => {
            object! {
                "size": loc.size.to_string(),
                "precision": {
                    "horizontal": loc.horizontal_precision,
                    "vertical": loc.vertical_precision,
                },
                "point": {
                    "latitude": loc.latitude.map(|e| e.to_string()),
                    "longitude": loc.longitude.map(|e| e.to_string()),
                    "altitude": loc.altitude.to_string(),
                },
            }
        }
        Record::MX(mx) => {
            object! {
                "preference": mx.preference,
                "exchange": mx.exchange.to_string(),
            }
        }
        Record::NAPTR(naptr) => {
            object! {
                "order": naptr.order,
                "flags": String::from_utf8_lossy(&naptr.flags).to_string(),
                "service": String::from_utf8_lossy(&naptr.service).to_string(),
                "regex": String::from_utf8_lossy(&naptr.regex).to_string(),
                "replacement": naptr.replacement.to_string(),
            }
        }
        Record::NS(ns) => {
            object! {
                "nameserver": ns.nameserver.to_string(),
            }
        }
        Record::OPENPGPKEY(opgp) => {
            object! {
                "key": opgp.base64_key(),
            }
        }
        Record::PTR(ptr) => {
            object! {
                "cname": ptr.cname.to_string(),
            }
        }
        Record::SSHFP(sshfp) => {
            object! {
                "algorithm": sshfp.algorithm,
                "fingerprint_type": sshfp.fingerprint_type,
                "fingerprint": sshfp.hex_fingerprint(),
            }
        }
        Record::SOA(soa) => {
            object! {
                "mname": soa.mname.to_string(),
            }
        }
        Record::SRV(srv) => {
            object! {
                "priority": srv.priority,
                "weight": srv.weight,
                "port": srv.port,
                "target": srv.target.to_string(),
            }
        }
        Record::TLSA(tlsa) => {
            object! {
                "certificate_usage": tlsa.certificate_usage,
                "selector": tlsa.selector,
                "matching_type": tlsa.matching_type,
                "certificate_data": tlsa.hex_certificate_data(),
            }
        }
        Record::TXT(txt) => {
            let ms = txt.messages.into_iter()
                        .map(|txt| String::from_utf8_lossy(&txt).to_string())
                        .collect::<Vec<_>>();
            object! {
                "messages": ms,
            }
        }
        Record::URI(uri) => {
            object! {
                "priority": uri.priority,
                "weight": uri.weight,
                "target": String::from_utf8_lossy(&uri.target).to_string(),
            }
        }
        Record::Other { bytes, .. } => {
            object! {
                "bytes": bytes,
            }
        }
    }
}


/// A wrapper around displaying characters that escapes quotes and
/// backslashes, and writes control and upper-bit bytes as their number rather
/// than their character. This is needed because even though such characters
/// are not allowed in domain names, packets can contain anything, and we need
/// a way to display the response, whatever it is.
struct Ascii<'a>(&'a [u8]);

impl fmt::Display for Ascii<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"")?;

        for byte in self.0.iter().copied() {
            if byte < 32 || byte >= 128 {
                write!(f, "\\{}", byte)?;
            }
            else if byte == b'"' {
                write!(f, "\\\"")?;
            }
            else if byte == b'\\' {
                write!(f, "\\\\")?;
            }
            else {
                write!(f, "{}", byte as char)?;
            }
        }

        write!(f, "\"")
    }
}


/// Prints a message describing the “error code” field of a DNS packet. This
/// happens when the packet was received correctly, but the server indicated
/// an error.
pub fn print_error_code(rcode: ErrorCode) {
    match rcode {
        ErrorCode::FormatError     => println!("Status: Format Error"),
        ErrorCode::ServerFailure   => println!("Status: Server Failure"),
        ErrorCode::NXDomain        => println!("Status: NXDomain"),
        ErrorCode::NotImplemented  => println!("Status: Not Implemented"),
        ErrorCode::QueryRefused    => println!("Status: Query Refused"),
        ErrorCode::BadVersion      => println!("Status: Bad Version"),
        ErrorCode::Private(num)    => println!("Status: Private Reason ({})", num),
        ErrorCode::Other(num)      => println!("Status: Other Failure ({})", num),
    }
}

/// Returns the “phase” of operation where an error occurred. This gets shown
/// to the user so they can debug what went wrong.
fn erroneous_phase(error: &TransportError) -> &'static str {
    match error {
        TransportError::AddrParseError(_)     => "parameter",
        TransportError::WireError(_)          => "protocol",
        TransportError::TruncatedResponse     |
        TransportError::NetworkError(_)       => "network",
        #[cfg(feature = "with_nativetls")]
        TransportError::TlsError(_)           |
        TransportError::TlsHandshakeError(_)  => "tls",
        #[cfg(feature = "with_rustls")]
        TransportError::RustlsInvalidDnsNameError(_) => "tls", // TODO: Actually wrong, could be https
        #[cfg(feature = "with_https")]
        TransportError::HttpError(_)          |
        TransportError::ReqwestError(_)          |
        TransportError::WrongHttpStatus(_,_)  => "http",
        TransportError::ProxyError(_) => "proxy",
    }
}

/// Formats an error into its human-readable message.
fn error_message(error: TransportError) -> String {
    match error {
        TransportError::AddrParseError(e)     => e.to_string(),
        TransportError::WireError(e)          => wire_error_message(e),
        TransportError::TruncatedResponse     => "Truncated response".into(),
        TransportError::NetworkError(e)       => e.to_string(),
        #[cfg(feature = "with_nativetls")]
        TransportError::TlsError(e)           => e.to_string(),
        #[cfg(feature = "with_nativetls")]
        TransportError::TlsHandshakeError(e)  => e.to_string(),
        #[cfg(any(feature = "with_rustls"))]
        TransportError::RustlsInvalidDnsNameError(e) => e.to_string(),
        TransportError::ProxyError(e) => e.to_string(),
        #[cfg(feature = "with_https")]
        TransportError::HttpError(e)          => e.to_string(),
        #[cfg(feature = "with_https")]
        TransportError::ReqwestError(e)          => e.to_string(),
        #[cfg(feature = "with_https")]
        TransportError::WrongHttpStatus(t,r)  => format!("Nameserver returned HTTP {} ({})", t, r.unwrap_or_else(|| "No reason".into()))
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
            format!("Malformed packet: record length should be {}, got {}", len, stated_length )
        }
        WireError::WrongRecordLength { stated_length, mandated_length: MandatedLength::AtLeast(len) } => {
            format!("Malformed packet: record length should be at least {}, got {}", len, stated_length )
        }
        WireError::WrongLabelLength { stated_length, length_after_labels } => {
            format!("Malformed packet: length {} was specified, but read {} bytes", stated_length, length_after_labels)
        }
        WireError::TooMuchRecursion(indices) => {
            format!("Malformed packet: too much recursion: {:?}", indices)
        }
        WireError::OutOfBounds(index) => {
            format!("Malformed packet: out of bounds ({})", index)
        }
        WireError::WrongVersion { stated_version, maximum_supported_version } => {
            format!("Malformed packet: record specifies version {}, expected up to {}", stated_version, maximum_supported_version)
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

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
}
