//! Rendering tables of DNS response results.

use std::time::Duration;

use ansi_term::ANSIString;

use dns::Answer;
use dns::record::Record;

use crate::colours::Colours;
use crate::output::TextFormat;


/// A **table** is built up from all the response records present in a DNS
/// packet. It then gets displayed to the user.
#[derive(Debug)]
pub struct Table {
    colours: Colours,
    text_format: TextFormat,
    rows: Vec<Row>,
}

/// A row of the table. This contains all the fields
#[derive(Debug)]
pub struct Row {
    qtype: ANSIString<'static>,
    qname: String,
    ttl: Option<String>,
    section: Section,
    summary: String,
}

/// The section of the DNS response that a record was read from.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum Section {

    /// This record was found in the **Answer** section.
    Answer,

    /// This record was found in the **Authority** section.
    Authority,

    /// This record was found in the **Additional** section.
    Additional,
}


impl Table {

    /// Create a new table with no rows.
    pub fn new(colours: Colours, text_format: TextFormat) -> Self {
        Self { colours, text_format, rows: Vec::new() }
    }

    /// Adds a row to the table, containing the data in the given answer in
    /// the right section.
    pub fn add_row(&mut self, answer: Answer, section: Section) {
        match answer {
            Answer::Standard { record, qname, ttl, .. } => {
                let qtype = self.coloured_record_type(&record);
                let qname = qname.to_string();
                let summary = self.text_format.record_payload_summary(record);
                let ttl = Some(self.text_format.format_duration(ttl));
                self.rows.push(Row { qtype, qname, ttl, summary, section });
            }
            Answer::Pseudo { qname, opt } => {
                let qtype = self.colours.opt.paint("OPT");
                let qname = qname.to_string();
                let summary = self.text_format.pseudo_record_payload_summary(opt);
                self.rows.push(Row { qtype, qname, ttl: None, summary, section });
            }
        }
    }

    /// Prints the formatted table to stdout.
    pub fn print(self, duration: Option<Duration>) {
        if ! self.rows.is_empty() {
            let qtype_len = self.max_qtype_len();
            let qname_len = self.max_qname_len();
            let ttl_len   = self.max_ttl_len();

            for r in &self.rows {
                for _ in 0 .. qtype_len - r.qtype.len() {
                    print!(" ");
                }

                print!("{} {} ", r.qtype, self.colours.qname.paint(&r.qname));

                for _ in 0 .. qname_len - r.qname.len() {
                    print!(" ");
                }

                if let Some(ttl) = &r.ttl {
                    for _ in 0 .. ttl_len - ttl.len() {
                        print!(" ");
                    }

                    print!("{}", ttl);
                }
                else {
                    for _ in 0 .. ttl_len {
                        print!(" ");
                    }
                }

                println!(" {} {}", self.format_section(r.section), r.summary);
            }
        }

        if let Some(dur) = duration {
            println!("Ran in {}ms", dur.as_millis());
        }
    }

    fn coloured_record_type(&self, record: &Record) -> ANSIString<'static> {
        match *record {
            Record::A(_)           => self.colours.a.paint("A"),
            Record::AAAA(_)        => self.colours.aaaa.paint("AAAA"),
            Record::CAA(_)         => self.colours.caa.paint("CAA"),
            Record::CNAME(_)       => self.colours.cname.paint("CNAME"),
            Record::EUI48(_)       => self.colours.eui48.paint("EUI48"),
            Record::EUI64(_)       => self.colours.eui64.paint("EUI64"),
            Record::HINFO(_)       => self.colours.hinfo.paint("HINFO"),
            Record::LOC(_)         => self.colours.loc.paint("LOC"),
            Record::MX(_)          => self.colours.mx.paint("MX"),
            Record::NAPTR(_)       => self.colours.ns.paint("NAPTR"),
            Record::NS(_)          => self.colours.ns.paint("NS"),
            Record::OPENPGPKEY(_)  => self.colours.openpgpkey.paint("OPENPGPKEY"),
            Record::PTR(_)         => self.colours.ptr.paint("PTR"),
            Record::SSHFP(_)       => self.colours.sshfp.paint("SSHFP"),
            Record::SOA(_)         => self.colours.soa.paint("SOA"),
            Record::SRV(_)         => self.colours.srv.paint("SRV"),
            Record::TLSA(_)        => self.colours.tlsa.paint("TLSA"),
            Record::TXT(_)         => self.colours.txt.paint("TXT"),
            Record::URI(_)         => self.colours.uri.paint("URI"),

            Record::Other { ref type_number, .. } => self.colours.unknown.paint(type_number.to_string()),
        }
    }

    fn max_qtype_len(&self) -> usize {
        self.rows.iter().map(|r| r.qtype.len()).max().unwrap()
    }

    fn max_qname_len(&self) -> usize {
        self.rows.iter().map(|r| r.qname.len()).max().unwrap()
    }

    fn max_ttl_len(&self) -> usize {
        self.rows.iter().map(|r| r.ttl.as_ref().map_or(0, String::len)).max().unwrap()
    }

    fn format_section(&self, section: Section) -> ANSIString<'static> {
        match section {
            Section::Answer      => self.colours.answer.paint(" "),
            Section::Authority   => self.colours.authority.paint("A"),
            Section::Additional  => self.colours.additional.paint("+"),
        }
    }
}
