//! Colours, colour schemes, and terminal styling.

use nu_ansi_term::Style;
use nu_ansi_term::Color::*;


/// The **colours** are used to paint the input.
#[derive(Debug, Default)]
pub struct Colours {
    pub qname: Style,

    pub answer: Style,
    pub authority: Style,
    pub additional: Style,

    pub a: Style,
    pub aaaa: Style,
    pub caa: Style,
    pub cname: Style,
    pub dnskey: Style,
    pub ds: Style,
    pub eui48: Style,
    pub eui64: Style,
    pub hinfo: Style,
    pub loc: Style,
    pub mx: Style,
    pub ns: Style,
    pub nsec: Style,
    pub naptr: Style,
    pub openpgpkey: Style,
    pub opt: Style,
    pub ptr: Style,
    pub rrsig: Style,
    pub sshfp: Style,
    pub soa: Style,
    pub srv: Style,
    pub tlsa: Style,
    pub txt: Style,
    pub uri: Style,
    pub unknown: Style,
}

/// Whether dog should colour what it writes to a stream, if the stream is a
/// terminal, going by the environment.
pub fn terminal_wants_colour(is_terminal: bool) -> bool {
    wants_colour(is_terminal, std::env::var_os("NO_COLOR").as_deref(), std::env::var_os("TERM").as_deref())
}

/// Whether a stream gets colours: only a terminal does, and not when the
/// user has set `NO_COLOR` to anything (<https://no-color.org>), nor when
/// `TERM` says the terminal cannot show them.
fn wants_colour(is_terminal: bool, no_color: Option<&std::ffi::OsStr>, term: Option<&std::ffi::OsStr>) -> bool {
    is_terminal && no_color.is_none_or(std::ffi::OsStr::is_empty) && term.is_none_or(|term| term != "dumb")
}

#[cfg(test)]
mod wants_colour_test {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn only_terminals_get_colours() {
        assert!(wants_colour(true, None, Some(OsStr::new("xterm-256color"))));
        assert!(wants_colour(true, None, None));
        assert!(!wants_colour(false, None, Some(OsStr::new("xterm"))));
    }

    /// `NO_COLOR` set to anything but the empty string turns colours off.
    #[test]
    fn no_color() {
        assert!(!wants_colour(true, Some(OsStr::new("1")), None));
        assert!(wants_colour(true, Some(OsStr::new("")), None));
    }

    /// A dumb terminal used to get escape codes it cannot show.
    #[test]
    fn dumb_terminals() {
        assert!(!wants_colour(true, None, Some(OsStr::new("dumb"))));
    }

    #[test]
    fn the_environment_is_read() {
        assert!(!terminal_wants_colour(false));
    }
}

impl Colours {

    /// Create a new colour palette that has a variety of different styles
    /// defined. This is used by default.
    pub fn pretty() -> Self {
        Self {
            qname: Blue.bold(),

            answer: Style::default(),
            authority: Cyan.normal(),
            additional: Green.normal(),

            a: Green.bold(),
            aaaa: Green.bold(),
            caa: Red.normal(),
            cname: Yellow.normal(),
            dnskey: Purple.normal(),
            ds: Purple.normal(),
            eui48: Yellow.normal(),
            eui64: Yellow.bold(),
            hinfo: Yellow.normal(),
            loc: Yellow.normal(),
            mx: Cyan.normal(),
            naptr: Green.normal(),
            ns: Red.normal(),
            nsec: Purple.normal(),
            openpgpkey: Cyan.normal(),
            opt: Purple.normal(),
            ptr: Red.normal(),
            rrsig: Purple.normal(),
            sshfp: Cyan.normal(),
            soa: Purple.normal(),
            srv: Cyan.normal(),
            tlsa: Yellow.normal(),
            txt: Yellow.normal(),
            uri: Yellow.normal(),
            unknown: White.on(Red),
        }
    }

    /// Create a new colour palette where no styles are defined, causing
    /// output to be rendered as plain text without any formatting.
    /// This is used when output is not to a terminal.
    pub fn plain() -> Self {
        Self::default()
    }
}


#[cfg(test)]
mod test {
    use super::*;

    // These are the escape sequences terminals have always been sent. Changing
    // the terminal-styling library must not change a byte of them.
    #[test]
    fn pretty_palette_escape_sequences() {
        let c = Colours::pretty();
        let (red, green, yellow, purple, cyan) = ("\x1b[31mx\x1b[0m", "\x1b[32mx\x1b[0m", "\x1b[33mx\x1b[0m", "\x1b[35mx\x1b[0m", "\x1b[36mx\x1b[0m");
        let cases = [
            ("qname", c.qname, "\x1b[1;34mx\x1b[0m"),
            ("answer", c.answer, "x"),
            ("authority", c.authority, cyan),
            ("additional", c.additional, green),
            ("a", c.a, "\x1b[1;32mx\x1b[0m"),
            ("aaaa", c.aaaa, "\x1b[1;32mx\x1b[0m"),
            ("caa", c.caa, red),
            ("cname", c.cname, yellow),
            ("dnskey", c.dnskey, purple),
            ("ds", c.ds, purple),
            ("eui48", c.eui48, yellow),
            ("eui64", c.eui64, "\x1b[1;33mx\x1b[0m"),
            ("hinfo", c.hinfo, yellow),
            ("loc", c.loc, yellow),
            ("mx", c.mx, cyan),
            ("naptr", c.naptr, green),
            ("ns", c.ns, red),
            ("nsec", c.nsec, purple),
            ("openpgpkey", c.openpgpkey, cyan),
            ("opt", c.opt, purple),
            ("ptr", c.ptr, red),
            ("rrsig", c.rrsig, purple),
            ("sshfp", c.sshfp, cyan),
            ("soa", c.soa, purple),
            ("srv", c.srv, cyan),
            ("tlsa", c.tlsa, yellow),
            ("txt", c.txt, yellow),
            ("uri", c.uri, yellow),
            ("unknown", c.unknown, "\x1b[41;37mx\x1b[0m"),
        ];

        for (field, style, expected) in cases {
            assert_eq!(style.paint("x").to_string(), expected, "{field}");
        }
    }

    #[test]
    fn plain_palette_has_no_escapes() {
        let c = Colours::plain();
        for style in [ c.qname, c.answer, c.a, c.opt, c.unknown ] {
            assert_eq!(style.paint("x").to_string(), "x");
        }
    }
}
