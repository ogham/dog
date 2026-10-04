//! Command-line option parsing.

use std::ffi::OsStr;
use std::fmt;
use std::time::Duration;

use log::*;

use dns::{QClass, Labels};
use dns::record::RecordType;

use crate::connect::TransportType;
use crate::output::{OutputFormat, UseColours, TextFormat};
use crate::requests::{RequestGenerator, Inputs, ProtocolTweaks, UseEDNS};
use crate::resolve::ResolverType;
use crate::txid::TxidGenerator;


/// The command-line options used when running dog.
#[derive(PartialEq, Debug)]
pub struct Options {

    /// The requests to make and how they should be generated.
    pub requests: RequestGenerator,

    /// Whether to display the time taken after every query.
    pub measure_time: bool,

    /// How to format the output data.
    pub format: OutputFormat,
}

impl Options {

    /// Parses and interprets a set of options from the user’s command-line
    /// arguments.
    ///
    /// This returns an `Ok` set of options if successful and running
    /// normally, a `Help` or `Version` variant if one of those options is
    /// specified, or an error variant if there’s an invalid option or
    /// inconsistency within the options after they were parsed.
    #[allow(unused_results)]
    pub fn getopts<C>(args: C) -> OptionsResult
    where C: IntoIterator,
          C::Item: AsRef<OsStr>,
    {
        let mut opts = getopts::Options::new();

        // Query options
        opts.optmulti("q", "query",       "Host name or domain name to query", "HOST");
        opts.optmulti("t", "type",        "Type of the DNS record being queried (A, MX, NS...)", "TYPE");
        opts.optmulti("n", "nameserver",  "Address of the nameserver to send packets to", "ADDR");
        opts.optmulti("",  "class",       "Network class of the DNS record being queried (IN, CH, HS)", "CLASS");

        // Sending options
        opts.optopt  ("",  "edns",         "Whether to OPT in to EDNS (disable, hide, show)", "SETTING");
        opts.optopt  ("",  "txid",         "Set the transaction ID to a specific value", "NUMBER");
        opts.optopt  ("",  "timeout",      "How long to wait for each answer, in seconds (default 5)", "SECONDS");
        opts.optmulti("Z", "",             "Set uncommon protocol tweaks", "TWEAKS");

        // Protocol options
        opts.optflag ("U", "udp",          "Use the DNS protocol over UDP");
        opts.optflag ("T", "tcp",          "Use the DNS protocol over TCP");
        opts.optflag ("S", "tls",          "Use the DNS-over-TLS protocol");
        opts.optflag ("H", "https",        "Use the DNS-over-HTTPS protocol");

        // Output options
        opts.optopt  ("",  "color",        "When to use terminal colors",  "WHEN");
        opts.optopt  ("",  "colour",       "When to use terminal colours", "WHEN");
        opts.optflag ("J", "json",         "Display the output as JSON");
        opts.optflag ("",  "seconds",      "Do not format durations, display them as seconds");
        opts.optflag ("1", "short",        "Short mode: display nothing but the first result");
        opts.optflag ("",  "time",         "Print how long the response took to arrive");

        // Meta options
        opts.optflag ("v", "version",      "Print version information");
        opts.optflag ("?", "help",         "Print list of command-line options");

        let matches = match opts.parse(args) {
            Ok(m)  => m,
            Err(e) => return OptionsResult::InvalidOptionsFormat(e),
        };

        let uc = match UseColours::deduce(&matches) {
            Ok(uc) => uc,
            Err(e) => return OptionsResult::InvalidOptions(e),
        };

        if matches.opt_present("version") {
            OptionsResult::Version(uc)
        }
        else if matches.opt_present("help") {
            OptionsResult::Help(HelpReason::Flag, uc)
        }
        else {
            match Self::deduce(matches, uc) {
                Ok(opts) => {
                    if opts.requests.inputs.domains.is_empty() {
                        OptionsResult::Help(HelpReason::NoDomains, uc)
                    }
                    else {
                        OptionsResult::Ok(opts)
                    }
                }
                Err(e) => {
                    OptionsResult::InvalidOptions(e)
                }
            }
        }
    }

    fn deduce(matches: getopts::Matches, use_colours: UseColours) -> Result<Self, OptionsError> {
        let measure_time = matches.opt_present("time");
        let format = OutputFormat::deduce(&matches, use_colours);
        let requests = RequestGenerator::deduce(matches)?;

        Ok(Self { requests, measure_time, format })
    }
}


impl RequestGenerator {
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let edns = UseEDNS::deduce(&matches)?;
        let txid_generator = TxidGenerator::deduce(&matches)?;
        let protocol_tweaks = ProtocolTweaks::deduce(&matches)?;
        protocol_tweaks.check_edns(edns)?;
        let timeout = deduce_timeout(&matches)?;
        let inputs = Inputs::deduce(matches)?;

        Ok(Self { inputs, txid_generator, edns, protocol_tweaks, timeout })
    }
}

/// The longest `--timeout` accepted: an hour. Anything longer is almost
/// certainly a mistake, and would leave dog apparently hung.
const MAX_TIMEOUT_SECONDS: f64 = 3600.0;

/// How long each transport waits for a nameserver: `--timeout` in seconds,
/// fractions allowed, or the transports' default. A caller that runs its own
/// recursive resolver sets it above the resolver's give-up time, so dog
/// reports the resolver's answer (SERVFAIL, say) instead of its own timeout.
fn deduce_timeout(matches: &getopts::Matches) -> Result<Duration, OptionsError> {
    let Some(input) = matches.opt_str("timeout") else {
        return Ok(dns_transport::DEFAULT_TIMEOUT);
    };

    match input.parse::<f64>() {
        Ok(seconds) if seconds > 0.0 && seconds <= MAX_TIMEOUT_SECONDS => Ok(Duration::from_secs_f64(seconds)),
        _ => Err(OptionsError::InvalidTimeout(input)),
    }
}


impl Inputs {
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let mut inputs = Self::default();
        inputs.load_transport_types(&matches)?;
        inputs.load_named_args(&matches)?;
        inputs.load_free_args(matches)?;
        inputs.check_for_missing_nameserver()?;
        inputs.load_fallbacks();
        Ok(inputs)
    }

    fn load_transport_types(&mut self, matches: &getopts::Matches) -> Result<(), OptionsError> {
        if matches.opt_present("https") {
            self.transport_types.push(Self::https_transport()?);
        }

        if matches.opt_present("tls") {
            self.transport_types.push(Self::tls_transport()?);
        }

        if matches.opt_present("tcp") {
            self.transport_types.push(TransportType::TCP);
        }

        if matches.opt_present("udp") {
            self.transport_types.push(TransportType::UDP);
        }

        Ok(())
    }

    #[cfg(feature = "with_tls")]
    #[allow(clippy::unnecessary_wraps)]  // it fails when TLS is compiled out
    fn tls_transport() -> Result<TransportType, OptionsError> {
        Ok(TransportType::TLS)
    }

    #[cfg(not(feature = "with_tls"))]
    fn tls_transport() -> Result<TransportType, OptionsError> {
        Err(OptionsError::FeatureDisabled { flag: "--tls", protocol: "TLS" })
    }

    #[cfg(feature = "with_https")]
    #[allow(clippy::unnecessary_wraps)]  // it fails when HTTPS is compiled out
    fn https_transport() -> Result<TransportType, OptionsError> {
        Ok(TransportType::HTTPS)
    }

    #[cfg(not(feature = "with_https"))]
    fn https_transport() -> Result<TransportType, OptionsError> {
        Err(OptionsError::FeatureDisabled { flag: "--https", protocol: "HTTPS" })
    }

    fn load_named_args(&mut self, matches: &getopts::Matches) -> Result<(), OptionsError> {
        for domain in matches.opt_strs("query") {
            self.add_domain(&domain)?;
        }

        for record_name in matches.opt_strs("type") {
            self.add_named_type(record_name)?;
        }

        for ns in matches.opt_strs("nameserver") {
            self.add_nameserver(&ns);
        }

        for class_name in matches.opt_strs("class") {
            self.add_named_class(class_name)?;
        }

        Ok(())
    }

    /// Adds a type given with `--type`: by name, in the generic form such as
    /// `TYPE65`, or as a number.
    fn add_named_type(&mut self, record_name: String) -> Result<(), OptionsError> {
        if record_name.eq_ignore_ascii_case("OPT") {
            Err(OptionsError::QueryTypeOPT)
        }
        else if let Some(record_type) = parse_type(&record_name).or_else(|| number(&record_name).map(RecordType::from)) {
            self.add_type(record_type);
            Ok(())
        }
        else {
            Err(OptionsError::InvalidQueryType(record_name))
        }
    }

    /// Adds a class given with `--class`: by name, in the generic form such
    /// as `CLASS3`, or as a number. A class with a name is the same class
    /// however it is given; before, `--class 1` was not IN, and the answer,
    /// which is for IN, was thrown away as answering some other question.
    fn add_named_class(&mut self, class_name: String) -> Result<(), OptionsError> {
        if let Some(class) = parse_class(&class_name).or_else(|| number(&class_name).map(QClass::from_u16)) {
            self.add_class(class);
            Ok(())
        }
        else {
            Err(OptionsError::InvalidQueryClass(class_name))
        }
    }

    fn load_free_args(&mut self, matches: getopts::Matches) -> Result<(), OptionsError> {
        for argument in matches.free {
            if let Some(nameserver) = argument.strip_prefix('@') {
                trace!("Got nameserver -> {nameserver:?}");
                self.add_nameserver(nameserver);
            }
            else if is_constant_name(&argument) {
                self.add_constant(&argument)?;
            }
            else {
                trace!("Got domain -> {:?}", &argument);
                self.add_domain(&argument)?;
            }
        }

        Ok(())
    }

    /// Adds a plain argument made of letters and digits, which could be a
    /// class, a type, or a domain of one label, guessed in that order.
    fn add_constant(&mut self, argument: &str) -> Result<(), OptionsError> {
        if argument.eq_ignore_ascii_case("OPT") {
            return Err(OptionsError::QueryTypeOPT);
        }

        if let Some(class) = parse_class(argument) {
            trace!("Got qclass -> {argument:?}");
            self.add_class(class);
        }
        else if let Some(record_type) = parse_type(argument) {
            trace!("Got qtype -> {argument:?}");
            self.add_type(record_type);
        }
        else {
            trace!("Got single-word domain -> {argument:?}");
            self.add_domain(argument)?;
        }

        Ok(())
    }

    /// Checks the nameservers given against the transports asked for, so a
    /// nameserver that can’t be used is refused before anything is sent.
    fn check_for_missing_nameserver(&self) -> Result<(), OptionsError> {
        #[cfg(feature = "with_https")]
        if self.resolver_types.is_empty() && self.transport_types == [TransportType::HTTPS] {
            return Err(OptionsError::MissingHttpsUrl);
        }

        let transports = if self.transport_types.is_empty() { &[ TransportType::Automatic ][..] } else { &self.transport_types };
        let nameservers = self.resolver_types.iter().filter_map(|r| if let ResolverType::Specific(ns) = r { Some(ns) } else { None });
        for nameserver in nameservers {
            check_nameserver(transports, nameserver)?;
        }

        Ok(())
    }

    fn load_fallbacks(&mut self) {
        if self.record_types.is_empty() {
            self.record_types.push(RecordType::A);
        }

        if self.classes.is_empty() {
            self.classes.push(QClass::IN);
        }

        if self.resolver_types.is_empty() {
            self.resolver_types.push(ResolverType::SystemDefault);
        }

        if self.transport_types.is_empty() {
            self.transport_types.push(TransportType::Automatic);
        }
    }

    fn add_domain(&mut self, input: &str) -> Result<(), OptionsError> {
        let domain = Labels::encode(input)
            .map_err(|e| OptionsError::InvalidDomain { domain: input.into(), reason: e.to_string() })?;
        self.domains.push(domain);
        Ok(())
    }

    fn add_type(&mut self, rt: RecordType) {
        self.record_types.push(rt);
    }

    fn add_nameserver(&mut self, input: &str) {
        self.resolver_types.push(ResolverType::Specific(input.into()));
    }

    fn add_class(&mut self, class: QClass) {
        self.classes.push(class);
    }
}

fn is_constant_name(argument: &str) -> bool {
    let Some(first_char) = argument.chars().next() else { return false };

    if ! first_char.is_ascii_alphabetic() {
        return false;
    }

    argument.chars().all(|c| c.is_ascii_alphanumeric())
}

/// A class by name, or in the generic form of RFC 3597 §5, such as `CLASS3`.
fn parse_class(input: &str) -> Option<QClass> {
    parse_class_name(input).or_else(|| generic_number(input, "CLASS").map(QClass::from_u16))
}

/// A type by name, or in the generic form of RFC 3597 §5, such as `TYPE65`.
fn parse_type(input: &str) -> Option<RecordType> {
    RecordType::from_type_name(input).or_else(|| generic_number(input, "TYPE").map(RecordType::from))
}

/// The number in a generic type or class, such as the 65 of `TYPE65`, with
/// the word in any case.
fn generic_number(input: &str, word: &str) -> Option<u16> {
    let start = input.get(.. word.len())?;
    if start.eq_ignore_ascii_case(word) { number(&input[word.len() ..]) } else { None }
}

/// A number made of nothing but digits that fits in 16 bits. Rust’s own
/// parsing would also take a leading plus sign.
fn number(input: &str) -> Option<u16> {
    if ! input.is_empty() && input.bytes().all(|b| b.is_ascii_digit()) { input.parse().ok() } else { None }
}

fn parse_class_name(input: &str) -> Option<QClass> {
    if input.eq_ignore_ascii_case("IN") {
        Some(QClass::IN)
    }
    else if input.eq_ignore_ascii_case("CH") {
        Some(QClass::CH)
    }
    else if input.eq_ignore_ascii_case("HS") {
        Some(QClass::HS)
    }
    else {
        None
    }
}

/// Checks that a nameserver can be used with every transport asked for.
fn check_nameserver(transports: &[TransportType], nameserver: &str) -> Result<(), OptionsError> {
    for transport in transports {
        transport.check_nameserver(nameserver)
            .map_err(|invalid| OptionsError::InvalidNameserver(invalid.to_string()))?;
    }

    Ok(())
}


impl TxidGenerator {
    fn deduce(matches: &getopts::Matches) -> Result<Self, OptionsError> {
        if let Some(starting_txid) = matches.opt_str("txid") {
            if let Some(start) = parse_dec_or_hex(&starting_txid) {
                Ok(Self::Sequence(start))
            }
            else {
                Err(OptionsError::InvalidTxid(starting_txid))
            }
        }
        else {
            Ok(Self::Random)
        }
    }
}

fn parse_dec_or_hex(input: &str) -> Option<u16> {
    if let Some(hex_str) = input.strip_prefix("0x") {
        match u16::from_str_radix(hex_str, 16) {
            Ok(num) => {
                Some(num)
            }
            Err(e) => {
                warn!("Error parsing hex number: {e}");
                None
            }
        }
    }
    else {
        match input.parse() {
            Ok(num) => {
                Some(num)
            }
            Err(e) => {
                warn!("Error parsing number: {e}");
                None
            }
        }
    }
}


impl OutputFormat {
    fn deduce(matches: &getopts::Matches, use_colours: UseColours) -> Self {
        if matches.opt_present("short") {
            let summary_format = TextFormat::deduce(matches);
            Self::Short(summary_format)
        }
        else if matches.opt_present("json") {
            Self::JSON
        }
        else {
            let summary_format = TextFormat::deduce(matches);
            Self::Text(use_colours, summary_format)
        }
    }
}


impl UseColours {

    /// The setting of `--colour` or `--color`, in any case. A setting dog
    /// does not know is refused; before, it quietly meant automatic.
    fn deduce(matches: &getopts::Matches) -> Result<Self, OptionsError> {
        let Some(setting) = matches.opt_str("color").or_else(|| matches.opt_str("colour")) else {
            return Ok(Self::Automatic);
        };

        match setting.to_ascii_lowercase().as_str() {
            "automatic" | "auto" | ""  => Ok(Self::Automatic),
            "always"    | "yes"        => Ok(Self::Always),
            "never"     | "no"         => Ok(Self::Never),
            _                          => Err(OptionsError::InvalidColour(setting)),
        }
    }
}


impl TextFormat {
    fn deduce(matches: &getopts::Matches) -> Self {
        let format_durations = ! matches.opt_present("seconds");
        Self { format_durations }
    }
}


impl UseEDNS {
    fn deduce(matches: &getopts::Matches) -> Result<Self, OptionsError> {
        if let Some(edns) = matches.opt_str("edns") {
            match edns.as_str() {
                "disable" | "off"  => Ok(Self::Disable),
                "hide"             => Ok(Self::SendAndHide),
                "show"             => Ok(Self::SendAndShow),
                oh                 => Err(OptionsError::InvalidEDNS(oh.into())),
            }
        }
        else {
            Ok(Self::SendAndHide)
        }
    }
}


impl ProtocolTweaks {
    fn deduce(matches: &getopts::Matches) -> Result<Self, OptionsError> {
        let mut tweaks = Self::default();

        for tweak_str in matches.opt_strs("Z") {
            // The help used to show `-Z=TWEAKS`, and no tweak starts with an
            // equals sign, so one is taken as part of the option.
            match tweak_str.strip_prefix('=').unwrap_or(&tweak_str) {
                "aa" | "authoritative" => {
                    tweaks.set_authoritative_flag = true;
                }
                "ad" | "authentic" => {
                    tweaks.set_authentic_flag = true;
                }
                "cd" | "checking-disabled" => {
                    tweaks.set_checking_disabled_flag = true;
                }
                "do" | "dnssec-ok" => {
                    tweaks.set_dnssec_ok_flag = true;
                }
                otherwise => {
                    if let Some(remaining_num) = otherwise.strip_prefix("bufsize=") {
                        match remaining_num.parse() {
                            Ok(parsed_bufsize) => {
                                tweaks.udp_payload_size = Some(parsed_bufsize);
                                continue;
                            }
                            Err(e) => {
                                warn!("Failed to parse buffer size: {e}");
                            }
                        }
                    }

                    return Err(OptionsError::InvalidTweak(otherwise.into()));
                }
            }
        }

        Ok(tweaks)
    }

    /// The DO bit and the buffer size are both sent in the OPT record, so
    /// asking for either with EDNS turned off asks for something that would
    /// not be sent; before, dog quietly left it out.
    fn check_edns(self, edns: UseEDNS) -> Result<(), OptionsError> {
        if edns.should_send() {
            Ok(())
        }
        else if self.set_dnssec_ok_flag {
            Err(OptionsError::TweakNeedsEDNS("do"))
        }
        else if self.udp_payload_size.is_some() {
            Err(OptionsError::TweakNeedsEDNS("bufsize"))
        }
        else {
            Ok(())
        }
    }
}


/// The result of the `Options::getopts` function.
#[derive(PartialEq, Debug)]
pub enum OptionsResult {

    /// The options were parsed successfully.
    Ok(Options),

    /// There was an error (from `getopts`) parsing the arguments.
    InvalidOptionsFormat(getopts::Fail),

    /// There was an error with the combination of options the user selected.
    InvalidOptions(OptionsError),

    /// Can’t run any checks because there’s help to display!
    Help(HelpReason, UseColours),

    /// One of the arguments was `--version`, to display the version number.
    Version(UseColours),
}

/// The reason that help is being displayed. If it’s for the `--help` flag,
/// then we shouldn’t return an error exit status.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum HelpReason {

    /// Help was requested with the `--help` flag.
    Flag,

    /// There were no domains being queried, so display help instead.
    /// Unlike `dig`, we don’t implicitly search for the root domain.
    NoDomains,
}

/// Something wrong with the combination of options the user has picked.
#[derive(PartialEq, Debug)]
pub enum OptionsError {
    InvalidDomain { domain: String, reason: String },
    InvalidColour(String),
    TweakNeedsEDNS(&'static str),
    InvalidEDNS(String),
    InvalidQueryType(String),
    InvalidQueryClass(String),
    InvalidTxid(String),
    InvalidTimeout(String),
    InvalidTweak(String),
    QueryTypeOPT,
    #[cfg(feature = "with_https")]
    MissingHttpsUrl,

    /// A nameserver cannot be used with a transport that was asked for,
    /// with the reason why.
    InvalidNameserver(String),

    /// A protocol was asked for that this build of dog was compiled
    /// without, with the flag that asked for it.
    #[cfg(any(not(feature = "with_tls"), not(feature = "with_https")))]
    FeatureDisabled { flag: &'static str, protocol: &'static str },
}

impl OptionsError {

    /// The message dog prints for this error, after its own name.
    pub fn report(&self) -> String {
        match self {
            #[cfg(any(not(feature = "with_tls"), not(feature = "with_https")))]
            Self::FeatureDisabled { .. } => self.to_string(),
            _ => format!("Invalid options: {self}"),
        }
    }
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain { domain, reason } => write!(f, "Invalid domain {domain:?}: {reason}"),
            Self::InvalidColour(colour)  => write!(f, "Invalid colour setting {colour:?} (use always, automatic, or never)"),
            Self::TweakNeedsEDNS(tweak)  => write!(f, "Protocol tweak {tweak:?} needs EDNS, which --edns disable turns off"),
            Self::InvalidEDNS(edns)      => write!(f, "Invalid EDNS setting {edns:?}"),
            Self::InvalidQueryType(qt)   => write!(f, "Invalid query type {qt:?}"),
            Self::InvalidQueryClass(qc)  => write!(f, "Invalid query class {qc:?}"),
            Self::InvalidTxid(txid)      => write!(f, "Invalid transaction ID {txid:?}"),
            Self::InvalidTimeout(t)      => write!(f, "Invalid timeout {t:?} (seconds, more than 0 and at most 3600)"),
            Self::InvalidTweak(tweak)    => write!(f, "Invalid protocol tweak {tweak:?}"),
            Self::QueryTypeOPT           => write!(f, "OPT request is sent by default (see -Z flag)"),
            #[cfg(feature = "with_https")]
            Self::MissingHttpsUrl        => write!(f, "You must pass a URL as a nameserver when using --https"),
            Self::InvalidNameserver(why) => write!(f, "{why}"),
            #[cfg(any(not(feature = "with_tls"), not(feature = "with_https")))]
            Self::FeatureDisabled { flag, protocol } => {
                write!(f, "Cannot use '{flag}': This version of dog has been compiled without {protocol} support")
            }
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;
    use dns::record::UnknownQtype;

    impl Inputs {
        fn fallbacks() -> Self {
            Inputs {
                domains:         vec![ /* No domains by default */ ],
                record_types:    vec![ RecordType::A ],
                classes:         vec![ QClass::IN ],
                resolver_types:  vec![ ResolverType::SystemDefault ],
                transport_types: vec![ TransportType::Automatic ],
            }
        }
    }

    impl OptionsResult {
        fn unwrap(self) -> Options {
            match self { Self::Ok(o) => o, other => panic!("{other:?}") }
        }
    }

    fn invalid(error: OptionsError) -> OptionsResult {
        OptionsResult::InvalidOptions(error)
    }

    /// dog does not query the root unless asked for it by name; an empty
    /// argument used to ask for it, quietly.
    #[test]
    fn an_empty_argument_is_not_a_domain() {
        assert_eq!(Options::getopts(&[ "" ]), invalid(OptionsError::InvalidDomain { domain: String::new(), reason: "it is empty".into() }));
        assert_eq!(Options::getopts(&[ "." ]).unwrap().requests.inputs.domains, vec![ Labels::root() ]);
    }

    #[test]
    fn invalid_domains_say_why() {
        assert_eq!(Options::getopts(&[ "a..b" ]), invalid(OptionsError::InvalidDomain { domain: "a..b".into(), reason: "it has an empty label".into() }));
        let error = OptionsError::InvalidDomain { domain: "\x1b[31mred".into(), reason: "why".into() };
        assert_eq!(error.report(), r#"Invalid options: Invalid domain "\u{1b}[31mred": why"#);
    }

    #[test]
    fn colour_settings() {
        let cases = [ ("always", UseColours::Always), ("ALWAYS", UseColours::Always), ("yes", UseColours::Always),
                      ("Never", UseColours::Never), ("no", UseColours::Never),
                      ("auto", UseColours::Automatic), ("automatic", UseColours::Automatic), ("", UseColours::Automatic) ];
        for (setting, expected) in cases {
            assert_eq!(Options::getopts(&[ "--version", &format!("--colour={setting}") ]), OptionsResult::Version(expected), "{setting:?}");
        }
    }

    /// An unknown colour setting used to mean automatic, without a word.
    #[test]
    fn an_unknown_colour_setting_is_refused() {
        assert_eq!(Options::getopts(&[ "--version", "--colour=sometimes" ]), invalid(OptionsError::InvalidColour("sometimes".into())));
        assert_eq!(Options::getopts(&[ "lookup.dog", "--color", "alwyas" ]), invalid(OptionsError::InvalidColour("alwyas".into())));
        assert_eq!(OptionsError::InvalidColour("alwyas".into()).to_string(), r#"Invalid colour setting "alwyas" (use always, automatic, or never)"#);
    }

    /// `--class 1` used to be a class numbered 1 that was not IN, and every
    /// answer, being for IN, was thrown away as answering something else.
    #[test]
    fn numbered_classes_are_the_named_classes() {
        let options = Options::getopts(&[ "lookup.dog", "--class", "1", "--class", "3", "--class", "4", "--class", "CLASS1", "--class", "class254" ]).unwrap();
        assert_eq!(options.requests.inputs.classes, vec![ QClass::IN, QClass::CH, QClass::HS, QClass::IN, QClass::Other(254) ]);
    }

    /// The generic forms of RFC 3597 used to be taken as domains when given
    /// plainly, and refused by `--type`.
    #[test]
    fn generic_types_and_classes() {
        let options = Options::getopts(&[ "lookup.dog", "TYPE65", "type1", "CLASS3", "-t", "TYPE28" ]).unwrap();
        assert_eq!(options.requests.inputs.record_types, vec![ RecordType::from(28), RecordType::from(65), RecordType::A ]);
        assert_eq!(options.requests.inputs.classes, vec![ QClass::CH ]);
        assert_eq!(options.requests.inputs.domains, vec![ Labels::encode("lookup.dog").unwrap() ]);
    }

    #[test]
    fn generic_forms_that_are_not_numbers() {
        let options = Options::getopts(&[ "TYPEX", "CLASS", "type99999" ]).unwrap();
        assert_eq!(options.requests.inputs.domains.len(), 3);
        assert_eq!(options.requests.inputs.record_types, vec![ RecordType::A ]);

        for bad in [ "TYPE+5", "+5", "TYPE", "tÿpe5" ] {
            assert_eq!(Options::getopts(&[ "lookup.dog", "-t", bad ]), invalid(OptionsError::InvalidQueryType(bad.into())), "{bad}");
        }
        assert_eq!(Options::getopts(&[ "lookup.dog", "--class", "CLASS" ]), invalid(OptionsError::InvalidQueryClass("CLASS".into())));
    }

    /// The help showed `-Z=TWEAKS`, which was refused as the tweak “=do”.
    #[test]
    fn tweaks_after_an_equals_sign() {
        let options = Options::getopts(&[ "dom.ain", "-Z=do", "-Z=bufsize=1232" ]).unwrap();
        assert!(options.requests.protocol_tweaks.set_dnssec_ok_flag);
        assert_eq!(options.requests.protocol_tweaks.udp_payload_size, Some(1232));
    }

    /// The DO bit and the buffer size go in the OPT record, which `--edns
    /// disable` leaves out; asking for both used to quietly send neither.
    #[test]
    fn tweaks_that_need_edns() {
        assert_eq!(Options::getopts(&[ "dom.ain", "-Z", "do", "--edns", "disable" ]), invalid(OptionsError::TweakNeedsEDNS("do")));
        assert_eq!(Options::getopts(&[ "dom.ain", "-Z", "bufsize=1232", "--edns", "off" ]), invalid(OptionsError::TweakNeedsEDNS("bufsize")));
        assert!(matches!(Options::getopts(&[ "dom.ain", "-Z", "aa", "--edns", "disable" ]), OptionsResult::Ok(_)));
        assert_eq!(OptionsError::TweakNeedsEDNS("do").report(), r#"Invalid options: Protocol tweak "do" needs EDNS, which --edns disable turns off"#);
    }

    // help tests

    #[test]
    fn help() {
        assert_eq!(Options::getopts(&[ "--help" ]),
                   OptionsResult::Help(HelpReason::Flag, UseColours::Automatic));
    }

    #[test]
    fn help_no_colour() {
        assert_eq!(Options::getopts(&[ "--help", "--colour=never" ]),
                   OptionsResult::Help(HelpReason::Flag, UseColours::Never));
    }

    #[test]
    fn version() {
        assert_eq!(Options::getopts(&[ "--version" ]),
                   OptionsResult::Version(UseColours::Automatic));
    }

    #[test]
    fn version_yes_color() {
        assert_eq!(Options::getopts(&[ "--version", "--color", "always" ]),
                   OptionsResult::Version(UseColours::Always));
    }

    #[test]
    fn fail() {
        assert_eq!(Options::getopts(&[ "--pear" ]),
                   OptionsResult::InvalidOptionsFormat(getopts::Fail::UnrecognizedOption("pear".into())));
    }

    #[test]
    fn empty() {
        let nothing: Vec<&str> = vec![];
        assert_eq!(Options::getopts(nothing),
                   OptionsResult::Help(HelpReason::NoDomains, UseColours::Automatic));
    }

    #[test]
    fn an_unrelated_argument() {
        assert_eq!(Options::getopts(&[ "--time" ]),
                   OptionsResult::Help(HelpReason::NoDomains, UseColours::Automatic));
    }

    // query tests

    #[test]
    fn just_domain() {
        let options = Options::getopts(&[ "lookup.dog" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains: vec![ Labels::encode("lookup.dog").unwrap() ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn just_named_domain() {
        let options = Options::getopts(&[ "-q", "lookup.dog" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains: vec![ Labels::encode("lookup.dog").unwrap() ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_type() {
        let options = Options::getopts(&[ "lookup.dog", "SOA" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ Labels::encode("lookup.dog").unwrap() ],
            record_types: vec![ RecordType::SOA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_type_lowercase() {
        let options = Options::getopts(&[ "lookup.dog", "soa" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ Labels::encode("lookup.dog").unwrap() ],
            record_types: vec![ RecordType::SOA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_other_type() {
        let options = Options::getopts(&[ "lookup.dog", "any" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ Labels::encode("lookup.dog").unwrap() ],
            record_types: vec![ RecordType::Other(UnknownQtype::from_type_name("ANY").unwrap()) ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_single_domain() {
        let options = Options::getopts(&[ "lookup.dog", "mixes" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ Labels::encode("lookup.dog").unwrap(),
                                Labels::encode("mixes").unwrap() ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_nameserver() {
        let options = Options::getopts(&[ "lookup.dog", "@1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ Labels::encode("lookup.dog").unwrap() ],
            resolver_types: vec![ ResolverType::Specific("1.1.1.1".into()) ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_class() {
        let options = Options::getopts(&[ "lookup.dog", "CH" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains: vec![ Labels::encode("lookup.dog").unwrap() ],
            classes: vec![ QClass::CH ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn domain_and_class_lowercase() {
        let options = Options::getopts(&[ "lookup.dog", "ch" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains: vec![ Labels::encode("lookup.dog").unwrap() ],
            classes: vec![ QClass::CH ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_free() {
        let options = Options::getopts(&[ "lookup.dog", "CH", "NS", "@1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ Labels::encode("lookup.dog").unwrap() ],
            classes:        vec![ QClass::CH ],
            record_types:   vec![ RecordType::NS ],
            resolver_types: vec![ ResolverType::Specific("1.1.1.1".into()) ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_parameters() {
        let options = Options::getopts(&[ "-q", "lookup.dog", "--class", "CH", "--type", "SOA", "--nameserver", "1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ Labels::encode("lookup.dog").unwrap() ],
            classes:        vec![ QClass::CH ],
            record_types:   vec![ RecordType::SOA ],
            resolver_types: vec![ ResolverType::Specific("1.1.1.1".into()) ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_parameters_lowercase() {
        let options = Options::getopts(&[ "-q", "lookup.dog", "--class", "ch", "--type", "soa", "--nameserver", "1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ Labels::encode("lookup.dog").unwrap() ],
            classes:        vec![ QClass::CH ],
            record_types:   vec![ RecordType::SOA ],
            resolver_types: vec![ ResolverType::Specific("1.1.1.1".into()) ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn two_types() {
        let options = Options::getopts(&[ "-q", "lookup.dog", "--type", "SRV", "--type", "AAAA" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ Labels::encode("lookup.dog").unwrap() ],
            record_types: vec![ RecordType::SRV, RecordType::AAAA ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn two_classes() {
        let options = Options::getopts(&[ "-q", "lookup.dog", "--class", "IN", "--class", "CH" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains: vec![ Labels::encode("lookup.dog").unwrap() ],
            classes: vec![ QClass::IN, QClass::CH ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_mixed_1() {
        let options = Options::getopts(&[ "lookup.dog", "--class", "CH", "SOA", "--nameserver", "1.1.1.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ Labels::encode("lookup.dog").unwrap() ],
            classes:        vec![ QClass::CH ],
            record_types:   vec![ RecordType::SOA ],
            resolver_types: vec![ ResolverType::Specific("1.1.1.1".into()) ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_mixed_2() {
        let options = Options::getopts(&[ "CH", "SOA", "MX", "IN", "-q", "lookup.dog", "--class", "HS" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ Labels::encode("lookup.dog").unwrap() ],
            classes:      vec![ QClass::HS, QClass::CH, QClass::IN ],
            record_types: vec![ RecordType::SOA, RecordType::MX ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn all_mixed_3() {
        let options = Options::getopts(&[ "lookup.dog", "--nameserver", "1.1.1.1", "--nameserver", "1.0.0.1" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:        vec![ Labels::encode("lookup.dog").unwrap() ],
            resolver_types: vec![ ResolverType::Specific("1.1.1.1".into()),
                                  ResolverType::Specific("1.0.0.1".into()), ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn explicit_numerics() {
        let options = Options::getopts(&[ "11", "--class", "22", "--type", "33" ]).unwrap();
        assert_eq!(options.requests.inputs, Inputs {
            domains:      vec![ Labels::encode("11").unwrap() ],
            classes:      vec![ QClass::Other(22) ],
            record_types: vec![ RecordType::from(33) ],
            .. Inputs::fallbacks()
        });
    }

    #[test]
    fn edns_and_tweaks() {
        let options = Options::getopts(&[ "dom.ain", "--edns", "show", "-Z", "authentic" ]).unwrap();
        assert_eq!(options.requests.edns, UseEDNS::SendAndShow);
        assert_eq!(options.requests.protocol_tweaks.set_authentic_flag, true);
    }

    #[test]
    fn two_more_tweaks() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "aa", "-Z", "cd" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_authoritative_flag, true);
        assert_eq!(options.requests.protocol_tweaks.set_checking_disabled_flag, true);
    }

    // --- DNSSEC OK (DO) flag tests ---

    #[test]
    fn dnssec_ok_tweak_short_form() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_tweak_long_form() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "dnssec-ok" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_default_is_false() {
        let options = Options::getopts(&[ "dom.ain" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, false);
    }

    #[test]
    fn dnssec_ok_with_ad() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "ad", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_authentic_flag, true);
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_with_cd() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "do", "-Z", "cd" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
        assert_eq!(options.requests.protocol_tweaks.set_checking_disabled_flag, true);
    }

    #[test]
    fn dnssec_ok_with_all_flags() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "aa", "-Z", "ad", "-Z", "cd", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_authoritative_flag, true);
        assert_eq!(options.requests.protocol_tweaks.set_authentic_flag, true);
        assert_eq!(options.requests.protocol_tweaks.set_checking_disabled_flag, true);
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_with_bufsize() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "do", "-Z", "bufsize=4096" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
        assert_eq!(options.requests.protocol_tweaks.udp_payload_size, Some(4096));
    }

    #[test]
    fn dnssec_ok_with_edns_show() {
        let options = Options::getopts(&[ "dom.ain", "--edns", "show", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.edns, UseEDNS::SendAndShow);
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_with_json() {
        let options = Options::getopts(&[ "dom.ain", "--json", "-Z", "do" ]).unwrap();
        assert_eq!(options.format, OutputFormat::JSON);
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_does_not_affect_other_flags() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
        assert_eq!(options.requests.protocol_tweaks.set_authoritative_flag, false);
        assert_eq!(options.requests.protocol_tweaks.set_authentic_flag, false);
        assert_eq!(options.requests.protocol_tweaks.set_checking_disabled_flag, false);
        assert_eq!(options.requests.protocol_tweaks.udp_payload_size, None);
    }

    #[test]
    fn dnssec_ok_duplicate_is_ok() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "do", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_both_aliases() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "do", "-Z", "dnssec-ok" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_with_record_type() {
        let options = Options::getopts(&[ "dom.ain", "DNSKEY", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.inputs.record_types, vec![ RecordType::DNSKEY ]);
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn dnssec_ok_with_nameserver() {
        let options = Options::getopts(&[ "dom.ain", "@1.1.1.1", "-Z", "do" ]).unwrap();
        assert_eq!(options.requests.inputs.resolver_types,
                   vec![ ResolverType::Specific("1.1.1.1".into()) ]);
        assert_eq!(options.requests.protocol_tweaks.set_dnssec_ok_flag, true);
    }

    #[test]
    fn timeout_defaults_to_the_transports_default() {
        let options = Options::getopts(&[ "dom.ain" ]).unwrap();
        assert_eq!(options.requests.timeout, dns_transport::DEFAULT_TIMEOUT);
    }

    #[test]
    fn timeout_in_seconds_with_fractions() {
        let options = Options::getopts(&[ "dom.ain", "--timeout", "15" ]).unwrap();
        assert_eq!(options.requests.timeout, Duration::from_secs(15));
        let options = Options::getopts(&[ "dom.ain", "--timeout=0.25" ]).unwrap();
        assert_eq!(options.requests.timeout, Duration::from_millis(250));
    }

    #[test]
    fn timeout_must_be_positive_and_at_most_an_hour() {
        for bad in [ "0", "-1", "3601", "soon", "", "NaN", "inf" ] {
            assert_eq!(Options::getopts(&[ "dom.ain", "--timeout", bad ]),
                       OptionsResult::InvalidOptions(OptionsError::InvalidTimeout(bad.into())), "{bad:?}");
        }
    }

    #[test]
    fn udp_size() {
        let options = Options::getopts(&[ "dom.ain", "-Z", "bufsize=4096" ]).unwrap();
        assert_eq!(options.requests.protocol_tweaks.udp_payload_size, Some(4096));
    }

    #[test]
    fn short_mode() {
        let tf = TextFormat { format_durations: true };
        let options = Options::getopts(&[ "dom.ain", "--short" ]).unwrap();
        assert_eq!(options.format, OutputFormat::Short(tf));
    }

    #[test]
    fn short_mode_seconds() {
        let tf = TextFormat { format_durations: false };
        let options = Options::getopts(&[ "dom.ain", "--short", "--seconds" ]).unwrap();
        assert_eq!(options.format, OutputFormat::Short(tf));
    }

    #[test]
    fn json_output() {
        let options = Options::getopts(&[ "dom.ain", "--json" ]).unwrap();
        assert_eq!(options.format, OutputFormat::JSON);
    }

    #[test]
    fn specific_txid() {
        let options = Options::getopts(&[ "dom.ain", "--txid", "1234" ]).unwrap();
        assert_eq!(options.requests.txid_generator,
                   TxidGenerator::Sequence(1234));
    }

    #[cfg(all(feature = "with_tls", feature = "with_https"))]
    #[test]
    fn all_transport_types() {
        use crate::connect::TransportType::*;

        let options = Options::getopts(&[ "dom.ain", "--https", "--tls", "--tcp", "--udp" ]).unwrap();
        assert_eq!(options.requests.inputs.transport_types,
                   vec![ HTTPS, TLS, TCP, UDP ]);
    }

    // invalid options tests

    #[test]
    fn invalid_named_class() {
        assert_eq!(Options::getopts(&[ "lookup.dog", "--class", "tubes" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidQueryClass("tubes".into())));
    }

    #[test]
    fn invalid_named_class_too_big() {
        assert_eq!(Options::getopts(&[ "lookup.dog", "--class", "999999" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidQueryClass("999999".into())));
    }

    #[test]
    fn invalid_named_type() {
        assert_eq!(Options::getopts(&[ "lookup.dog", "--type", "tubes" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidQueryType("tubes".into())));
    }

    #[test]
    fn invalid_named_type_too_big() {
        assert_eq!(Options::getopts(&[ "lookup.dog", "--type", "999999" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidQueryType("999999".into())));
    }

    #[test]
    fn invalid_txid() {
        assert_eq!(Options::getopts(&[ "lookup.dog", "--txid=0x10000" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidTxid("0x10000".into())));
    }

    #[test]
    fn invalid_edns() {
        assert_eq!(Options::getopts(&[ "--edns=yep" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidEDNS("yep".into())));
    }

    #[test]
    fn invalid_tweaks() {
        assert_eq!(Options::getopts(&[ "-Zsleep" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidTweak("sleep".into())));
    }

    #[test]
    fn invalid_udp_size() {
        assert_eq!(Options::getopts(&[ "-Z", "bufsize=null" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidTweak("bufsize=null".into())));
    }

    #[test]
    fn invalid_udp_size_size() {
        assert_eq!(Options::getopts(&[ "-Z", "bufsize=999999999" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidTweak("bufsize=999999999".into())));
    }

    #[test]
    fn invalid_udp_size_missing() {
        assert_eq!(Options::getopts(&[ "-Z", "bufsize=" ]),
                   OptionsResult::InvalidOptions(OptionsError::InvalidTweak("bufsize=".into())));
    }

    #[cfg(feature = "with_https")]
    #[test]
    fn missing_https_url() {
        assert_eq!(Options::getopts(&[ "--https", "lookup.dog" ]),
                   OptionsResult::InvalidOptions(OptionsError::MissingHttpsUrl));
    }

    #[test]
    fn errors_are_reported_as_invalid_options() {
        assert_eq!(OptionsError::QueryTypeOPT.report(),
                   "Invalid options: OPT request is sent by default (see -Z flag)");
    }

    #[cfg(not(feature = "with_tls"))]
    #[test]
    fn tls_compiled_out() {
        let result = Options::getopts(&[ "--tls", "lookup.dog" ]);
        let error = OptionsError::FeatureDisabled { flag: "--tls", protocol: "TLS" };
        assert_eq!(error.report(), "Cannot use '--tls': This version of dog has been compiled without TLS support");
        assert_eq!(result, OptionsResult::InvalidOptions(error));
    }

    #[cfg(not(feature = "with_https"))]
    #[test]
    fn https_compiled_out() {
        let result = Options::getopts(&[ "--https", "lookup.dog", "@https://example.com/dns-query" ]);
        let error = OptionsError::FeatureDisabled { flag: "--https", protocol: "HTTPS" };
        assert_eq!(error.report(), "Cannot use '--https': This version of dog has been compiled without HTTPS support");
        assert_eq!(result, OptionsResult::InvalidOptions(error));
    }

    // opt tests

    #[test]
    fn opt() {
        assert_eq!(Options::getopts(&[ "OPT", "lookup.dog" ]),
                   OptionsResult::InvalidOptions(OptionsError::QueryTypeOPT));
    }

    #[test]
    fn opt_lowercase() {
        assert_eq!(Options::getopts(&[ "opt", "lookup.dog" ]),
                   OptionsResult::InvalidOptions(OptionsError::QueryTypeOPT));
    }

    #[test]
    fn opt_arg() {
        assert_eq!(Options::getopts(&[ "-t", "OPT", "lookup.dog" ]),
                   OptionsResult::InvalidOptions(OptionsError::QueryTypeOPT));
    }

    #[test]
    fn opt_arg_lowercase() {
        assert_eq!(Options::getopts(&[ "-t", "opt", "lookup.dog" ]),
                   OptionsResult::InvalidOptions(OptionsError::QueryTypeOPT));
    }

    // txid tests

    #[test]
    fn number_parsing() {
        assert_eq!(parse_dec_or_hex("1234"),    Some(1234));
        assert_eq!(parse_dec_or_hex("0x1234"),  Some(0x1234));
        assert_eq!(parse_dec_or_hex("0xABcd"),  Some(0xABCD));

        assert_eq!(parse_dec_or_hex("65536"),   None);
        assert_eq!(parse_dec_or_hex("0x65536"), None);

        assert_eq!(parse_dec_or_hex(""),        None);
        assert_eq!(parse_dec_or_hex("0x"),      None);
    }
}
