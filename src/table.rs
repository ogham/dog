//! Rendering tables of DNS response results.

use std::time::Duration;

use nu_ansi_term::AnsiString;

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
    qtype: AnsiString<'static>,
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
                self.rows.push(Row { qtype, qname, ttl, section, summary });
            }
            Answer::Pseudo { qname, opt } => {
                let qtype = self.colours.opt.paint("OPT");
                let qname = qname.to_string();
                let summary = TextFormat::pseudo_record_payload_summary(&opt);
                self.rows.push(Row { qtype, qname, ttl: None, summary, section });
            }
        }
    }

    /// Writes the formatted table, then how long the query took, if that
    /// was measured.
    ///
    /// # Errors
    ///
    /// Returns an error if the output cannot be written to.
    pub fn print(self, out: &mut impl std::io::Write, duration: Option<Duration>) -> std::io::Result<()> {
        for line in self.lines() {
            writeln!(out, "{line}")?;
        }

        if let Some(dur) = duration {
            writeln!(out, "Ran in {}ms", dur.as_millis())?;
        }

        Ok(())
    }

    /// Every row as a line of text, with the columns lined up.
    fn lines(&self) -> Vec<String> {
        if self.rows.is_empty() {
            return Vec::new();
        }

        let widths = Widths { qtype: self.max_qtype_len(), qname: self.max_qname_len(), ttl: self.max_ttl_len() };
        self.rows.iter().map(|row| self.format_row(row, &widths)).collect()
    }

    fn format_row(&self, row: &Row, widths: &Widths) -> String {
        let ttl = match &row.ttl {
            Some(ttl)  => format!("{}{}", padding(widths.ttl - ttl.len()), ttl),
            None       => padding(widths.ttl),
        };

        format!("{}{} {} {}{} {} {}",
            padding(widths.qtype - row.qtype.as_str().len()),
            row.qtype,
            self.colours.qname.paint(&row.qname),
            padding(widths.qname - row.qname.len()),
            ttl,
            self.format_section(row.section),
            row.summary,
        )
    }

    fn coloured_record_type(&self, record: &Record) -> AnsiString<'static> {
        match *record {
            Record::A(_)           => self.colours.a.paint("A"),
            Record::AAAA(_)        => self.colours.aaaa.paint("AAAA"),
            Record::CAA(_)         => self.colours.caa.paint("CAA"),
            Record::CNAME(_)       => self.colours.cname.paint("CNAME"),
            Record::DNSKEY(_)      => self.colours.dnskey.paint("DNSKEY"),
            Record::DS(_)          => self.colours.ds.paint("DS"),
            Record::EUI48(_)       => self.colours.eui48.paint("EUI48"),
            Record::EUI64(_)       => self.colours.eui64.paint("EUI64"),
            Record::HINFO(_)       => self.colours.hinfo.paint("HINFO"),
            Record::LOC(_)         => self.colours.loc.paint("LOC"),
            Record::MX(_)          => self.colours.mx.paint("MX"),
            Record::NAPTR(_)       => self.colours.naptr.paint("NAPTR"),
            Record::NS(_)          => self.colours.ns.paint("NS"),
            Record::NSEC(_)        => self.colours.nsec.paint("NSEC"),
            Record::OPENPGPKEY(_)  => self.colours.openpgpkey.paint("OPENPGPKEY"),
            Record::PTR(_)         => self.colours.ptr.paint("PTR"),
            Record::RRSIG(_)       => self.colours.rrsig.paint("RRSIG"),
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
        self.rows.iter().map(|r| r.qtype.as_str().len()).max().unwrap()
    }

    fn max_qname_len(&self) -> usize {
        self.rows.iter().map(|r| r.qname.len()).max().unwrap()
    }

    fn max_ttl_len(&self) -> usize {
        self.rows.iter().map(|r| r.ttl.as_ref().map_or(0, String::len)).max().unwrap()
    }

    fn format_section(&self, section: Section) -> AnsiString<'static> {
        match section {
            Section::Answer      => self.colours.answer.paint(" "),
            Section::Authority   => self.colours.authority.paint("A"),
            Section::Additional  => self.colours.additional.paint("+"),
        }
    }
}

/// How wide each padded column of the table is.
struct Widths {
    qtype: usize,
    qname: usize,
    ttl: usize,
}

fn padding(width: usize) -> String {
    " ".repeat(width)
}


#[cfg(test)]
mod test {
    use super::*;
    use std::io;
    use dns::Response;
    use test_support::fixtures;

    fn table_of(fixture: &str) -> Table {
        let response = Response::from_bytes(&fixtures::response(fixture)).unwrap();
        let mut table = Table::new(Colours::plain(), TextFormat { format_durations: true });
        for answer in response.answers {
            table.add_row(answer, Section::Answer);
        }
        for answer in response.additionals {
            table.add_row(answer, Section::Additional);
        }
        table
    }

    fn render(table: Table, duration: Option<Duration>) -> String {
        let mut out = Vec::new();
        table.print(&mut out, duration).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// The real answer for a CNAME chain has types and names of different
    /// lengths; the types are right-aligned and the names start together.
    #[test]
    fn columns_line_up() {
        let text = render(table_of("a-via-cname"), None);
        let lines = text.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 4, "{text}");

        for (line, qtype) in lines.iter().zip([ "CNAME", "A", "A", "OPT" ]) {
            assert_eq!(line[.. 5].trim_start(), qtype, "{line:?}");
            assert_eq!(&line[5 .. 6], " ", "{line:?}");
        }

        let section_column = |line: &str| line.find(" + ").or_else(|| line.find("    ")).unwrap();
        assert_eq!(section_column(lines[1]), section_column(lines[2]));
    }

    /// Where the A record shows its TTL, the OPT pseudo-record, which has
    /// none, shows only spaces.
    #[test]
    fn pseudo_records_have_no_ttl() {
        let text = render(table_of("a-example"), None);
        let a_line = text.lines().find(|line| line.trim_start().starts_with("A ")).unwrap();
        let opt_line = text.lines().find(|line| line.trim_start().starts_with("OPT ")).unwrap();

        let ttl = a_line.split_whitespace().nth(2).unwrap();
        let ttl_start = a_line.find(ttl).unwrap();
        let ttl_column = ttl_start .. ttl_start + ttl.len();

        assert!(opt_line[ttl_column].chars().all(|c| c == ' '), "{a_line:?}\n{opt_line:?}");
        assert!(opt_line.contains(" + "), "{opt_line:?}");
    }

    #[test]
    fn an_empty_table_prints_only_the_time() {
        let empty = || Table::new(Colours::plain(), TextFormat { format_durations: true });
        assert_eq!(render(empty(), None), "");
        assert_eq!(render(empty(), Some(Duration::from_millis(12))), "Ran in 12ms\n");
    }

    struct Closed;

    impl io::Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn write_failures_are_returned() {
        io::Write::flush(&mut Closed).unwrap();
        assert_eq!(table_of("a-example").print(&mut Closed, None).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        let empty = Table::new(Colours::plain(), TextFormat { format_durations: true });
        assert!(empty.print(&mut Closed, Some(Duration::ZERO)).is_err());
    }
}
