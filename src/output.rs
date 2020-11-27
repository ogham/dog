//! Text and JSON output.

use std::time::Duration;

use dns::{Response, Query, Answer, ErrorCode, WireError, MandatedLength};
use dns::record::{Record, OPT, UnknownQtype};
use dns_transport::Error as TransportError;
use serde_json::{json, Value as JsonValue};

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
        self == Self::Always || (atty::is(atty::Stream::Stdout) && self != Self::Never)
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
                            println!("{}", tf.record_payload_summary(&record))
                        }
                        Answer::Pseudo { opt, .. } => {
                            println!("{}", tf.pseudo_record_payload_summary(&opt))
                        }
                    }

                }
            }
            Self::JSON => {
                let mut rs = Vec::new();

                for response in responses {
                    let json = json!({
                        "queries": json_queries(&response.queries),
                        "answers": json_answers(&response.answers),
                        "authorities": json_answers(&response.authorities),
                        "additionals": json_answers(&response.additionals),
                    });

                    rs.push(json);
                }

                if let Some(duration) = duration {
                    let object = json!({ "responses": rs, "duration": duration });
                    println!("{}", object);
                }
                else {
                    let object = json!({ "responses": rs });
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

    /// Print an error that’s ocurred while sending or receiving DNS packets
    /// to standard error.
    pub fn print_error(self, error: TransportError) {
        match self {
            Self::Short(..) | Self::Text(..) => {
                eprintln!("Error [{}]: {}", erroneous_phase(&error), error_message(error));
            }

            Self::JSON => {
                let object = json!({
                    "error": true,
                    "error_phase": erroneous_phase(&error),
                    "error_message": error_message(error),
                });

                eprintln!("{}", object);
            }
        }
    }
}

impl TextFormat {

    /// Formats a summary of a record in a received DNS response. Each record
    /// type contains wildly different data, so the format of the summary
    /// depends on what record it’s for.
    pub fn record_payload_summary(self, record: &Record) -> String {
        match *record {
            Record::A(ref a) => {
                format!("{}", a.address)
            }
            Record::AAAA(ref aaaa) => {
                format!("{}", aaaa.address)
            }
            Record::CAA(ref caa) => {
                if caa.critical {
                    format!("{:?} {:?} (critical)", caa.tag, caa.value)
                }
                else {
                    format!("{:?} {:?} (non-critical)", caa.tag, caa.value)
                }
            }
            Record::CNAME(ref cname) => {
                format!("{:?}", cname.domain.to_string())
            }
            Record::EUI48(ref eui48) => {
                format!("{:?}", eui48.formatted_address())
            }
            Record::HINFO(ref hinfo) => {
                format!("{:?} {:?}", hinfo.cpu, hinfo.os)
            }
            Record::LOC(ref loc) => {
                format!("{} ({}, {}) ({}, {}, {})",
                    loc.size,
                    loc.horizontal_precision,
                    loc.vertical_precision,
                    loc.latitude .map_or_else(|| "Out of range".into(), |e| e.to_string()),
                    loc.longitude.map_or_else(|| "Out of range".into(), |e| e.to_string()),
                    loc.altitude,
                )
            }
            Record::MX(ref mx) => {
                format!("{} {:?}", mx.preference, mx.exchange.to_string())
            }
            Record::NAPTR(ref naptr) => {
                format!("{} {} {} {:?} /{}/ {:?}",
                    naptr.order,
                    naptr.preference,
                    naptr.flags,
                    naptr.service,
                    naptr.regex,
                    naptr.replacement.to_string(),
                )
            }
            Record::NS(ref ns) => {
                format!("{:?}", ns.nameserver.to_string())
            }
            Record::OPENPGPKEY(ref opgp) => {
                format!("{:?}", opgp.base64_key())
            }
            Record::PTR(ref ptr) => {
                format!("{:?}", ptr.cname.to_string())
            }
            Record::SSHFP(ref sshfp) => {
                format!("{} {} {}",
                    sshfp.algorithm,
                    sshfp.fingerprint_type,
                    sshfp.hex_fingerprint(),
                )
            }
            Record::SOA(ref soa) => {
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
            Record::SRV(ref srv) => {
                format!("{} {} {:?}:{}", srv.priority, srv.weight, srv.target.to_string(), srv.port)
            }
            Record::TLSA(ref tlsa) => {
                format!("{} {} {} {:?}",
                    tlsa.certificate_usage,
                    tlsa.selector,
                    tlsa.matching_type,
                    tlsa.hex_certificate_data(),
                )
            }
            Record::TXT(ref txt) => {
                let messages = txt.messages.iter().map(|t| format!("{:?}", t)).collect::<Vec<_>>();
                messages.join(", ")
            }
            Record::URI(ref uri) => {
                format!("{} {} {:?}", uri.priority, uri.weight, uri.target)
            }
            Record::Other { ref bytes, .. } => {
                format!("{:?}", bytes)
            }
        }
    }

    /// Formats a summary of an OPT pseudo-record. Pseudo-records have a different
    /// structure than standard ones.
    pub fn pseudo_record_payload_summary(self, opt: &OPT) -> String {
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
fn json_queries(queries: &[Query]) -> JsonValue {
    let queries = queries.iter().map(|q| {
        json!({
            "name": q.qname.to_string(),
            "class": format!("{:?}", q.qclass),
            "type": q.qtype,
        })
    }).collect::<Vec<_>>();

    json!(queries)
}

/// Serialises multiple received DNS answers as a JSON value.
fn json_answers(answers: &[Answer]) -> JsonValue {
    let answers = answers.iter().map(|a| {
        match a {
            Answer::Standard { qname, qclass, ttl, record } => {
                let mut object = json_record(record);
                let omut = object.as_object_mut().unwrap();
                omut.insert("name".into(), qname.to_string().into());
                omut.insert("class".into(), format!("{:?}", qclass).into());
                omut.insert("ttl".into(), (*ttl).into());
                json!(object)
            }
            Answer::Pseudo { qname, opt } => {
                let object = json!({
                    "name": qname.to_string(),
                    "type": "OPT",
                    "version": opt.edns0_version,
                    "data": opt.data,
                });

                object
            }
        }
    }).collect::<Vec<_>>();

    json!(answers)
}

/// Serialises a received DNS record as a JSON value.
fn json_record(record: &Record) -> JsonValue {
    match record {
        Record::A(a) => {
            json!({
                "type": "A",
                "address": a.address.to_string(),
            })
        }
        Record::AAAA(aaaa) => {
            json!({
                "type": "AAAA",
                "address": aaaa.address.to_string(),
            })
        }
        Record::CAA(caa) => {
            json!({
                "type": "CAA",
                "critical": caa.critical,
                "tag": caa.tag,
                "value": caa.value,
            })
        }
        Record::CNAME(cname) => {
            json!({
                "type": "CNAME",
                "domain": cname.domain.to_string(),
            })
        }
        Record::EUI48(eui48) => {
            json!({
                "type": "EUI48",
                "identifier": eui48.formatted_address(),
            })
        }
        Record::HINFO(hinfo) => {
            json!({
                "type": "HINFO",
                "cpu": hinfo.cpu,
                "os": hinfo.os,
            })
        }
        Record::LOC(loc) => {
            json!({
                "type": "LOC",
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
            })
        }
        Record::MX(mx) => {
            json!({
                "type": "MX",
                "preference": mx.preference,
                "exchange": mx.exchange.to_string(),
            })
        }
        Record::NAPTR(naptr) => {
            json!({
                "type": "NAPTR",
                "order": naptr.order,
                "flags": naptr.flags,
                "service": naptr.service,
                "regex": naptr.service,
                "replacement": naptr.replacement.to_string(),
            })
        }
        Record::NS(ns) => {
            json!({
                "type": "NS",
                "nameserver": ns.nameserver.to_string(),
            })
        }
        Record::OPENPGPKEY(opgp) => {
            json!({
                "type": "OPENPGPKEY",
                "key": opgp.base64_key(),
            })
        }
        Record::PTR(ptr) => {
            json!({
                "type": "PTR",
                "cname": ptr.cname.to_string(),
            })
        }
        Record::SSHFP(sshfp) => {
            json!({
                "type": "SSHFP",
                "algorithm": sshfp.algorithm,
                "fingerprint_type": sshfp.fingerprint_type,
                "fingerprint": sshfp.hex_fingerprint(),
            })
        }
        Record::SOA(soa) => {
            json!({
                "type": "SOA",
                "mname": soa.mname.to_string(),
            })
        }
        Record::SRV(srv) => {
            json!({
                "type": "SRV",
                "priority": srv.priority,
                "weight": srv.weight,
                "port": srv.port,
                "target": srv.target.to_string(),
            })
        }
        Record::TLSA(tlsa) => {
            json!({
                "type": "TLSA",
                "certificate_usage": tlsa.certificate_usage,
                "selector": tlsa.selector,
                "matching_type": tlsa.matching_type,
                "certificate_data": tlsa.hex_certificate_data(),
            })
        }
        Record::TXT(txt) => {
            json!({
                "type": "TXT",
                "messages": txt.messages,
            })
        }
        Record::URI(uri) => {
            json!({
                "type": "URI",
                "priority": uri.priority,
                "weight": uri.weight,
                "target": uri.target,
            })
        }
        Record::Other { type_number, bytes } => {
            let type_name = match type_number {
                UnknownQtype::HeardOf(name) => json!(name),
                UnknownQtype::UnheardOf(num) => json!(num),
            };

            json!({
                "unknown": true,
                "type": type_name,
                "bytes": bytes,
            })
        }
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
        TransportError::WireError(_)          => "protocol",
        TransportError::TruncatedResponse     |
        TransportError::NetworkError(_)       => "network",
        #[cfg(feature="tls")]
        TransportError::TlsError(_)           |
        TransportError::TlsHandshakeError(_)  => "tls",
        #[cfg(feature="https")]
        TransportError::HttpError(_)          |
        TransportError::WrongHttpStatus(_,_)  => "http",
    }
}

/// Formats an error into its human-readable message.
fn error_message(error: TransportError) -> String {
    match error {
        TransportError::WireError(e)          => wire_error_message(e),
        TransportError::TruncatedResponse     => "Truncated response".into(),
        TransportError::NetworkError(e)       => e.to_string(),
        #[cfg(feature="tls")]
        TransportError::TlsError(e)           => e.to_string(),
        #[cfg(feature="tls")]
        TransportError::TlsHandshakeError(e)  => e.to_string(),
        #[cfg(feature="https")]
        TransportError::HttpError(e)          => e.to_string(),
        #[cfg(feature="https")]
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
