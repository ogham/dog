//! Colours, colour schemes, and terminal styling.

use ansi_term::Style;
use ansi_term::Color::*;


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
    pub hinfo: Style,
    pub loc: Style,
    pub mx: Style,
    pub ns: Style,
    pub opt: Style,
    pub ptr: Style,
    pub sshfp: Style,
    pub soa: Style,
    pub srv: Style,
    pub tlsa: Style,
    pub txt: Style,
    pub unknown: Style,
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
            hinfo: Yellow.normal(),
            loc: Yellow.normal(),
            mx: Cyan.normal(),
            ns: Red.normal(),
            opt: Purple.normal(),
            ptr: Red.normal(),
            sshfp: Cyan.normal(),
            soa: Purple.normal(),
            srv: Cyan.normal(),
            tlsa: Yellow.normal(),
            txt: Yellow.normal(),
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
