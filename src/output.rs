//! Text and JSON output.

use std::time::Duration;

use dns::{Response, Query, Answer, ErrorCode, WireError};
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
                        "queries": self.json_queries(&response.queries),
                        "answers": self.json_answers(&response.answers),
                        "authorities": self.json_answers(&response.authorities),
                        "additionals": self.json_answers(&response.additionals),
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

fn erroneous_phase(error: &TransportError) -> &'static str {
	match error {
		TransportError::NetworkError(_)  => "network",
		TransportError::HttpError(_)     => "http",
		TransportError::TlsError(_)      => "tls",
		TransportError::BadRequest       => "http-status",
		TransportError::WireError(_)     => "protocol",
	}
}

fn error_message(error: TransportError) -> String {
	match error {
		TransportError::NetworkError(e)  => e.to_string(),
		TransportError::HttpError(e)     => e.to_string(),
		TransportError::TlsError(e)      => e.to_string(),
		TransportError::BadRequest       => "Nameserver returned HTTP 400 Bad Request".into(),
		TransportError::WireError(e)     => wire_error_message(e),
	}
}

fn wire_error_message(error: WireError) -> String {
    match error {
        WireError::IO                                   => "Malformed packet: insufficient data".into(),
        WireError::WrongRecordLength { expected, got }  => format!("Malformed packet: expected length {}, got {}", expected, got),
        WireError::WrongLabelLength { expected, got }   => format!("Malformed packet: expected length {}, got {}", expected, got),
        WireError::TooMuchRecursion(indices)            => format!("Malformed packet: too much recursion: {:?}", indices),
        WireError::OutOfBounds(index)                   => format!("Malformed packet: out of bounds ({})", index),
    }
}


impl TextFormat {
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
            Record::MX(ref mx) => {
                format!("{} {:?}", mx.preference, mx.exchange.to_string())
            }
            Record::NS(ref ns) => {
                format!("{:?}", ns.nameserver.to_string())
            }
            Record::PTR(ref ptr) => {
                format!("{:?}", ptr.cname.to_string())
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
            Record::TXT(ref txt) => {
                format!("{:?}", txt.message)
            }
            Record::Other { ref bytes, .. } => {
                format!("{:?}", bytes)
            }
        }
    }

    pub fn pseudo_record_payload_summary(self, opt: &OPT) -> String {
        format!("{} {} {} {} {:?}",
            opt.udp_payload_size,
            opt.higher_bits,
            opt.edns0_version,
            opt.flags,
            opt.data)
    }

    pub fn format_duration(self, seconds: u32) -> String {
        if ! self.format_durations {
            format!("{}", seconds)
        }
        else if seconds < 60 {
            format!("{}s", seconds)
        }
        else if seconds < 60 * 60 {
            format!("{}m{:02}s", seconds / 60, seconds % 60)
        }
        else if seconds < 60 * 60 * 24{
            format!("{}h{:02}m{:02}s", seconds / 3600, (seconds % 3600) / 60, seconds % 60)
        }
        else {
            format!("{}d{}h{:02}m{:02}s", seconds / 86400, (seconds % 86400) / 3600, (seconds % 3600) / 60, seconds % 60)
        }
    }
}

impl OutputFormat {
    fn json_queries(self, queries: &[Query]) -> JsonValue {
        let queries = queries.iter().map(|q| {
            json!({
                "name": q.qname.to_string(),
                "class": format!("{:?}", q.qclass),
                "type": q.qtype,
            })
        }).collect::<Vec<_>>();

        json!(queries)
    }

    fn json_answers(self, answers: &[Answer]) -> JsonValue {
        let answers = answers.iter().map(|a| {
            match a {
                Answer::Standard { qname, qclass, ttl, record } => {
                    let mut object = self.json_record(record);
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

    fn json_record(self, record: &Record) -> JsonValue {
        match record {
            Record::A(rec)      => json!({ "type": "A",     "address": rec.address.to_string() }),
            Record::AAAA(rec)   => json!({ "type": "AAAA",  "address": rec.address.to_string() }),
            Record::CAA(rec)    => json!({ "type": "CAA",   "critical": rec.critical, "tag": rec.tag, "value": rec.value }),
            Record::CNAME(rec)  => json!({ "type": "CNAME", "domain": rec.domain.to_string() }),
            Record::MX(rec)     => json!({ "type": "MX",    "preference": rec.preference, "exchange": rec.exchange.to_string() }),
            Record::NS(rec)     => json!({ "type": "NS",    "nameserver": rec.nameserver.to_string() }),
            Record::PTR(rec)    => json!({ "type": "PTR",   "cname": rec.cname.to_string() }),
            Record::SOA(rec)    => json!({ "type": "SOA",   "mname": rec.mname.to_string() }),
            Record::SRV(rec)    => json!({ "type": "SRV",   "priority": rec.priority, "weight": rec.weight, "port": rec.port, "target": rec.target.to_string() }),
            Record::TXT(rec)    => json!({ "type": "TXT",   "message": rec.message }),
            Record::Other { type_number, bytes } => {
                let type_name = match type_number {
                    UnknownQtype::HeardOf(name) => json!(name),
                    UnknownQtype::UnheardOf(num) => json!(num),
                };
                json!({ "unknown": true, "type": type_name, "bytes": bytes })
            }
        }
    }
}

pub fn print_error_code(rcode: ErrorCode) {
    match rcode {
        ErrorCode::FormatError     => println!("Status: Format Error"),
        ErrorCode::ServerFailure   => println!("Status: Server Failure"),
        ErrorCode::NXDomain        => println!("Status: NXDomain"),
        ErrorCode::NotImplemented  => println!("Status: Not Implemented"),
        ErrorCode::QueryRefused    => println!("Status: Query Refused"),
        ErrorCode::BadVersion      => println!("Status: Bad Version"),
        ErrorCode::Other(num)      => println!("Status: Other Failure ({})", num),
    }
}
