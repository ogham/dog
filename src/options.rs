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

    /// Time-out for requests.
    pub timeout: Option<Duration>,
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
        opts.optmulti("Z", "",             "Set uncommon protocol tweaks", "TWEAKS");
        opts.optopt  ("",  "timeout",      "Time-out for the request", "NUMBER");

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

        let uc = UseColours::deduce(&matches);

        if matches.opt_present("version") {
            OptionsResult::Version(uc)
        }
        else if matches.opt_present("help") {
            OptionsResult::Help(HelpReason::Flag, uc)
        }
        else {
            match Self::deduce(matches) {
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

    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let measure_time = matches.opt_present("time");
        let format = OutputFormat::deduce(&matches);
        let timeout = TimeOut::deduce(&matches)?;
        let requests = RequestGenerator::deduce(matches)?;

        Ok(Self { requests, measure_time, format, timeout })
    }
}


impl RequestGenerator {
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let edns = UseEDNS::deduce(&matches)?;
        let txid_generator = TxidGenerator::deduce(&matches)?;
        let protocol_tweaks = ProtocolTweaks::deduce(&matches)?;
        let inputs = Inputs::deduce(matches)?;

        Ok(Self { inputs, txid_generator, edns, protocol_tweaks })
    }
}


impl Inputs {
    fn deduce(matches: getopts::Matches) -> Result<Self, OptionsError> {
        let mut inputs = Self::default();
        inputs.load_transport_types(&matches);
        inputs.load_named_args(&matches)?;
        inputs.load_free_args(matches)?;
        inputs.check_for_missing_nameserver()?;
        inputs.load_fallbacks();
        Ok(inputs)
    }

    fn load_transport_types(&mut self, matches: &getopts::Matches) {
        if matches.opt_present("https") {
            self.transport_types.push(TransportType::HTTPS);
        }

        if matches.opt_present("tls") {
            self.transport_types.push(TransportType::TLS);
        }

        if matches.opt_present("tcp") {
            self.transport_types.push(TransportType::TCP);
        }

        if matches.opt_present("udp") {
            self.transport_types.push(TransportType::UDP);
        }
    }

    fn load_named_args(&mut self, matches: &getopts::Matches) -> Result<(), OptionsError> {
        for domain in matches.opt_strs("query") {
            self.add_domain(&domain)?;
        }

        for record_name in matches.opt_strs("type") {
            if record_name.eq_ignore_ascii_case("OPT") {
                return Err(OptionsError::QueryTypeOPT);
            }
            else if let Some(record_type) = RecordType::from_type_name(&record_name) {
                self.add_type(record_type);
            }
            else if let Ok(type_number) = record_name.parse::<u16>() {
                self.record_types.push(RecordType::from(type_number));
            }
            else {
                return Err(OptionsError::InvalidQueryType(record_name));
            }
        }

        for ns in matches.opt_strs("nameserver") {
            self.add_nameserver(&ns);
        }

        for class_name in matches.opt_strs("class") {
            if let Some(class) = parse_class_name(&class_name) {
                self.add_class(class);
            }
            else if let Ok(class_number) = class_name.parse() {
                self.add_class(QClass::Other(class_number));
            }
            else {
                return Err(OptionsError::InvalidQueryClass(class_name));
            }
        }

        Ok(())
    }

    fn load_free_args(&mut self, matches: getopts::Matches) -> Result<(), OptionsError> {
        for argument in matches.free {
            if let Some(nameserver) = argument.strip_prefix('@') {
                trace!("Got nameserver -> {:?}", nameserver);
                self.add_nameserver(nameserver);
            }
            else if is_constant_name(&argument) {
                if argument.eq_ignore_ascii_case("OPT") {
                    return Err(OptionsError::QueryTypeOPT);
                }
                else if let Some(class) = parse_class_name(&argument) {
                    trace!("Got qclass -> {:?}", &argument);
                    self.add_class(class);
                }
                else if let Some(record_type) = RecordType::from_type_name(&argument) {
                    trace!("Got qtype -> {:?}", &argument);
                    self.add_type(record_type);
                }
                else {
                    trace!("Got single-word domain -> {:?}", &argument);
                    self.add_domain(&argument)?;
                }
            }
            else {
                trace!("Got domain -> {:?}", &argument);
                self.add_domain(&argument)?;
            }
        }

        Ok(())
    }

    fn check_for_missing_nameserver(&self) -> Result<(), OptionsError> {
        if self.resolver_types.is_empty() && self.transport_types == [TransportType::HTTPS] {
            Err(OptionsError::MissingHttpsUrl)
        }
        else {
            Ok(())
        }
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
        if let Ok(domain) = Labels::encode(input) {
            self.domains.push(domain);
            Ok(())
        }
        else {
            Err(OptionsError::InvalidDomain(input.into()))
        }
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
    let first_char = match argument.chars().next() {
        Some(c)  => c,
        None     => return false,
    };

    if ! first_char.is_ascii_alphabetic() {
        return false;
    }

    argument.chars().all(|c| c.is_ascii_alphanumeric())
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
                warn!("Error parsing hex number: {}", e);
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
                warn!("Error parsing number: {}", e);
                None
            }
        }
    }
}

struct TimeOut;
impl TimeOut {
    fn deduce(matches: &getopts::Matches) -> Result<Option<Duration>, OptionsError> {
        if let Some(starting_timeout) = matches.opt_str("timeout") {
            if let Ok(d) = starting_timeout.parse::<u64>() {
                if d == 0 {
                    return Err(OptionsError::InvalidTimeOut(starting_timeout));
                }
                return Ok(Some(Duration::from_secs(d)));
            }
            return Err(OptionsError::InvalidTimeOut(starting_timeout));
        }
        Ok(None)
    }
}

impl OutputFormat {
    fn deduce(matches: &getopts::Matches) -> Self {
        if matches.opt_present("short") {
            let summary_format = TextFormat::deduce(matches);
            Self::Short(summary_format)
        }
        else if matches.opt_present("json") {
            Self::JSON
        }
        else {
            let use_colours = UseColours::deduce(matches);
            let summary_format = TextFormat::deduce(matches);
            Self::Text(use_colours, summary_format)
        }
    }
}


impl UseColours {
    fn deduce(matches: &getopts::Matches) -> Self {
        match matches.opt_str("color").or_else(|| matches.opt_str("colour")).unwrap_or_default().as_str() {
            "automatic" | "auto" | ""  => Self::Automatic,
            "always"    | "yes"        => Self::Always,
            "never"     | "no"         => Self::Never,
            otherwise => {
                warn!("Unknown colour setting {:?}", otherwise);
                Self::Automatic
            },
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
            match &*tweak_str {
                "aa" | "authoritative" => {
                    tweaks.set_authoritative_flag = true;
                }
                "ad" | "authentic" => {
                    tweaks.set_authentic_flag = true;
                }
                "cd" | "checking-disabled" => {
                    tweaks.set_checking_disabled_flag = true;
                }
                otherwise => {
                    if let Some(remaining_num) = tweak_str.strip_prefix("bufsize=") {
                        match remaining_num.parse() {
                            Ok(parsed_bufsize) => {
                                tweaks.udp_payload_size = Some(parsed_bufsize);
                                continue;
                            }
                            Err(e) => {
                                warn!("Failed to parse buffer size: {}", e);
                            }
                        }
                    }

                    return Err(OptionsError::InvalidTweak(otherwise.into()));
                }
            }
        }

        Ok(tweaks)
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
    InvalidDomain(String),
    InvalidEDNS(String),
    InvalidQueryType(String),
    InvalidQueryClass(String),
    InvalidTxid(String),
    InvalidTweak(String),
    InvalidTimeOut(String),
    QueryTypeOPT,
    MissingHttpsUrl,
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain(domain)  => write!(f, "Invalid domain {:?}", domain),
            Self::InvalidEDNS(edns)      => write!(f, "Invalid EDNS setting {:?}", edns),
            Self::InvalidQueryType(qt)   => write!(f, "Invalid query type {:?}", qt),
            Self::InvalidQueryClass(qc)  => write!(f, "Invalid query class {:?}", qc),
            Self::InvalidTxid(txid)      => write!(f, "Invalid transaction ID {:?}", txid),
            Self::InvalidTweak(tweak)    => write!(f, "Invalid protocol tweak {:?}", tweak),
            Self::InvalidTimeOut(timeout)=> write!(f, "Invalid time-out {:?}", timeout),
            Self::QueryTypeOPT           => write!(f, "OPT request is sent by default (see -Z flag)"),
            Self::MissingHttpsUrl        => write!(f, "You must pass a URL as a nameserver when using --https"),
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
            match self {
                Self::Ok(o)  => o,
                _            => panic!("{:?}", self),
            }
        }
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

    #[test]
    fn missing_https_url() {
        assert_eq!(Options::getopts(&[ "--https", "lookup.dog" ]),
                   OptionsResult::InvalidOptions(OptionsError::MissingHttpsUrl));
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
        assert_eq!(parse_dec_or_hex("0xABcd"),  Some(0xABcd));

        assert_eq!(parse_dec_or_hex("65536"),   None);
        assert_eq!(parse_dec_or_hex("0x65536"), None);

        assert_eq!(parse_dec_or_hex(""),        None);
        assert_eq!(parse_dec_or_hex("0x"),      None);
    }
}
