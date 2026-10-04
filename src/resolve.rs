//! Specifying the address of the DNS server to send requests to.

use std::fmt;
use std::io;

use log::*;

use dns::Labels;

use crate::system::SystemPaths;


/// A **resolver type** is the source of a `Resolver`.
#[derive(PartialEq, Debug)]
pub enum ResolverType {

    /// Obtain a resolver by consulting the system in order to find a
    /// nameserver and a search list.
    SystemDefault,

    /// Obtain a resolver by using the given user-submitted string.
    Specific(String),
}

impl ResolverType {

    /// Obtains a resolver by the means specified in this type. Returns an
    /// error if there was a problem looking up system information, or if
    /// there is no suitable nameserver available.
    pub fn obtain(self, paths: &SystemPaths) -> Result<Resolver, ResolverLookupError> {
        match self {
            Self::SystemDefault => {
                system_nameservers(paths)
            }
            Self::Specific(nameserver) => {
                let search_list = Vec::new();
                Ok(Resolver { nameservers: vec![ nameserver ], search_list })
            }
        }
    }
}


/// A **resolver** knows the addresses of the servers we should
/// send DNS requests to, and the search list for name lookup.
#[derive(Debug)]
pub struct Resolver {

    /// The addresses of the nameservers, in the order to try them.
    pub nameservers: Vec<String>,

    /// The search list for name lookup.
    pub search_list: Vec<String>,
}

impl Resolver {

    /// The nameservers that queries should be sent to, each to be tried if
    /// the one before it does not answer.
    pub fn nameservers(&self) -> &[String] {
        &self.nameservers
    }

    /// Returns a sequence of names to be queried, taking into account
    /// the search list.
    pub fn name_list(&self, name: &Labels) -> Vec<Labels> {
        let mut list = Vec::new();

        if name.len() > 1 {
            list.push(name.clone());
            return list;
        }

        for search in &self.search_list {
            match Labels::encode(search) {
                Ok(suffix)  => list.push(name.extend(&suffix)),
                Err(_)      => warn!("Invalid search list: {search}"),
            }
        }

        list.push(name.clone());
        list
    }
}


/// Looks up the system default nameserver on Unix, by reading
/// `/etc/resolv.conf` and using the first line that specifies one.
#[cfg(unix)]
fn system_nameservers(paths: &SystemPaths) -> Result<Resolver, ResolverLookupError> {
    use std::fs::File;
    use std::io::BufReader;

    debug!("Reading nameservers from {}", paths.resolv_conf.display());
    let file = File::open(&paths.resolv_conf)?;
    parse_resolv_conf(BufReader::new(file))
}

/// How many of the nameservers in `resolv.conf` are used: the same number
/// as the system’s own resolver uses (glibc’s `MAXNS`).
#[cfg(unix)]
const MAX_NAMESERVERS: usize = 3;

/// Finds the nameservers, IPv4 and IPv6 alike, and the last search list, in
/// text in the `resolv.conf` format. Returns an error if there’s a problem
/// reading it, or if it specifies no usable nameserver. Only IPv4 ones used
/// to be read, which left a host with only IPv6 nameservers with none.
#[cfg(unix)]
fn parse_resolv_conf(reader: impl io::BufRead) -> Result<Resolver, ResolverLookupError> {
    let mut nameservers = Vec::new();
    let mut search_list = Vec::new();
    for line in reader.lines() {
        let line = line?;

        if let Some(nameserver_str) = line.strip_prefix("nameserver ") {
            let nameserver_str = nameserver_str.trim();
            match nameserver_str.parse::<std::net::IpAddr>() {
                Ok(_ip) => nameservers.push(nameserver_str.into()),
                Err(e)  => warn!("Failed to parse nameserver line {line:?}: {e}"),
            }
        }

        if let Some(search_str) = line.strip_prefix("search ") {
            search_list.clear();
            search_list.extend(search_str.split_ascii_whitespace().map(std::convert::Into::into));
        }
    }

    if nameservers.is_empty() {
        return Err(ResolverLookupError::NoNameserver);
    }

    nameservers.truncate(MAX_NAMESERVERS);
    Ok(Resolver { nameservers, search_list })
}


/// Looks up the system default nameserver on Windows, by iterating through
/// the list of network adapters and returning the first nameserver it finds.
#[cfg(windows)]
#[allow(unused)]  // todo: Remove this when the time is right
fn system_nameservers(_paths: &SystemPaths) -> Result<Resolver, ResolverLookupError> {
    use std::net::{IpAddr, UdpSocket};

    // According to the specification, prefer ipv6 by default.
    // TODO: add control flag to select an ip family.
    #[derive(Debug, PartialEq)]
    enum ForceIPFamily {
        V4,
        V6,
        None,
    }

    // get the IP of the Network adapter that is used to access the Internet
    // https://stackoverflow.com/questions/24661022/getting-ip-adress-associated-to-real-hardware-ethernet-controller-in-windows-c
    fn get_ipv4() -> io::Result<IpAddr> {
        let s = UdpSocket::bind("0.0.0.0:0")?;
        s.connect("8.8.8.8:53")?;
        let addr = s.local_addr()?;
        Ok(addr.ip())
    }

    fn get_ipv6() -> io::Result<IpAddr> {
        let s = UdpSocket::bind("[::1]:0")?;
        s.connect("[2001:4860:4860::8888]:53")?;
        let addr = s.local_addr()?;
        Ok(addr.ip())
    }

    let force_ip_family: ForceIPFamily = ForceIPFamily::None;
    let ip = match force_ip_family {
        ForceIPFamily::V4 => get_ipv4().ok(),
        ForceIPFamily::V6 => get_ipv6().ok(),
        ForceIPFamily::None => get_ipv6().or(get_ipv4()).ok(),
    };

    let search_list = Vec::new();  // todo: implement this

    let adapters = ipconfig::get_adapters()?;
    let active_adapters = adapters.iter().filter(|a| {
        a.oper_status() == ipconfig::OperStatus::IfOperStatusUp && !a.gateways().is_empty()
    });

    if let Some(dns_server) = active_adapters
        .clone()
        .find(|a| ip.map(|ip| a.ip_addresses().contains(&ip)).unwrap_or(false))
        .and_then(|a| a.dns_servers().first())
    {
        debug!("Found first nameserver {:?}", dns_server);
        let nameservers = vec![ dns_server.to_string() ];
        Ok(Resolver { nameservers, search_list })
    }

    // Fallback
    else if let Some(dns_server) = active_adapters
        .flat_map(|a| a.dns_servers())
        .find(|d| (d.is_ipv4() && force_ip_family != ForceIPFamily::V6) || d.is_ipv6())
    {
        debug!("Found first fallback nameserver {:?}", dns_server);
        let nameservers = vec![ dns_server.to_string() ];
        Ok(Resolver { nameservers, search_list })
    }

    else {
        Err(ResolverLookupError::NoNameserver)
    }
}


/// The fall-back system default nameserver determinator that is not very
/// determined as it returns nothing without actually checking anything.
#[cfg(all(not(unix), not(windows)))]
fn system_nameservers(_paths: &SystemPaths) -> Result<Resolver, ResolverLookupError> {
    warn!("Unable to fetch default nameservers on this platform.");
    Err(ResolverLookupError::UnsupportedPlatform)
}


/// Something that can go wrong while obtaining a `Resolver`.
#[derive(Debug)]
pub enum ResolverLookupError {

    /// The system information was successfully read, but there was no adapter
    /// suitable to use.
    NoNameserver,

    /// There was an error accessing the network configuration.
    IO(io::Error),

    /// There was an error accessing the network configuration (extra errors
    /// that can only happen on Windows).
    #[cfg(windows)]
    Windows(ipconfig::error::Error),

    /// dog is running on a platform where it doesn’t know how to get the
    /// network configuration, so the user must supply one instead.
    #[cfg(all(not(unix), not(windows)))]
    UnsupportedPlatform,
}

impl From<io::Error> for ResolverLookupError {
    fn from(error: io::Error) -> ResolverLookupError {
        Self::IO(error)
    }
}

#[cfg(windows)]
impl From<ipconfig::error::Error> for ResolverLookupError {
    fn from(error: ipconfig::error::Error) -> ResolverLookupError {
        Self::Windows(error)
    }
}

impl fmt::Display for ResolverLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNameserver => {
                write!(f, "No nameserver found")
            }
            Self::IO(ioe) => {
                write!(f, "Error reading network configuration: {ioe}")
            }
            #[cfg(windows)]
            Self::Windows(ipe) => {
                write!(f, "Error reading network configuration: {}", ipe)
            }
            #[cfg(all(not(unix), not(windows)))]
            Self::UnsupportedPlatform => {
                write!(f, "dog cannot automatically detect nameservers on this platform; you will have to provide one explicitly")
            }
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    fn labels(name: &str) -> Labels {
        Labels::encode(name).unwrap()
    }

    /// Reading `resolv.conf` is how the system nameserver is found on unix;
    /// Windows asks the OS instead, so these tests only exist on unix.
    #[cfg(unix)]
    mod resolv_conf_files {
        use super::super::*;
        use std::path::PathBuf;
        use test_support::fixtures;

        fn resolv_conf(name: &str) -> Result<Resolver, ResolverLookupError> {
            let paths = SystemPaths { hosts: PathBuf::new(), resolv_conf: fixtures::root().join("etc").join(name) };
            ResolverType::SystemDefault.obtain(&paths)
        }

        #[test]
        fn docker_resolv_conf() {
            let resolver = resolv_conf("resolv.conf.docker").unwrap();
            assert_eq!(resolver.nameservers(), [ "192.0.2.53" ]);
            assert_eq!(resolver.search_list, [ "corp.example.", "example.org." ]);
        }

        /// A commented-out nameserver line is not a nameserver.
        #[test]
        fn debian_resolv_conf() {
            let resolver = resolv_conf("resolv.conf.debian").unwrap();
            assert_eq!(resolver.nameservers(), [ "192.0.2.53" ]);
        }

        /// Every nameserver is used, in order, IPv6 ones too; before, only
        /// the first IPv4 one was, so dog never tried another.
        #[test]
        fn networkmanager_resolv_conf() {
            let resolver = resolv_conf("resolv.conf.networkmanager").unwrap();
            assert_eq!(resolver.nameservers(), [ "2001:db8::1", "192.0.2.1", "192.0.2.2" ]);
            assert_eq!(resolver.search_list, [ "example.org" ]);
        }

        #[test]
        fn systemd_resolved_stub() {
            let resolver = resolv_conf("resolv.conf.systemd-resolved").unwrap();
            assert_eq!(resolver.nameservers(), [ "127.0.0.53" ]);
            assert_eq!(resolver.search_list, [ "." ]);
        }

        /// A host with only IPv6 nameservers used to have none as far as dog
        /// could tell.
        #[test]
        fn only_ipv6_nameservers() {
            let resolver = parse_resolv_conf(&b"nameserver 2001:db8::53\nnameserver ::1 \n"[..]).unwrap();
            assert_eq!(resolver.nameservers(), [ "2001:db8::53", "::1" ]);
        }

        /// As with the system’s own resolver, only the first three are used,
        /// and one that is not an address, such as a scoped link-local one,
        /// is skipped.
        #[test]
        fn at_most_three_nameservers() {
            let text = "nameserver fe80::1%eth0\nnameserver 192.0.2.1\nnameserver 192.0.2.2\nnameserver 192.0.2.3\nnameserver 192.0.2.4\n";
            assert_eq!(parse_resolv_conf(text.as_bytes()).unwrap().nameservers(), [ "192.0.2.1", "192.0.2.2", "192.0.2.3" ]);
        }

        #[test]
        fn a_file_with_no_nameserver() {
            let error = resolv_conf("hosts.docker").unwrap_err();
            assert_eq!(error.to_string(), "No nameserver found");
        }

        #[test]
        fn a_missing_file() {
            let error = resolv_conf("no-such-file").unwrap_err();
            assert!(error.to_string().starts_with("Error reading network configuration: No such file"), "{error}");
        }

        #[test]
        fn the_last_search_line_wins_and_bad_lines_are_skipped() {
            let text = "search first.example\nnameserver not-an-address\nnameserver 192.0.2.9\nsearch second.example third.example\n";
            let resolver = parse_resolv_conf(text.as_bytes()).unwrap();
            assert_eq!(resolver.nameservers(), [ "192.0.2.9" ]);
            assert_eq!(resolver.search_list, [ "second.example", "third.example" ]);
        }

        #[test]
        fn invalid_utf8_is_an_error() {
            let error = parse_resolv_conf(&b"nameserver 192.0.2.1\n\xff\n"[..]).unwrap_err();
            assert!(matches!(error, ResolverLookupError::IO(_)));
        }
    }

    #[test]
    fn a_specific_nameserver_has_no_search_list() {
        let resolver = ResolverType::Specific("192.0.2.7:5353".into()).obtain(&SystemPaths::system()).unwrap();
        assert_eq!(resolver.nameservers(), [ "192.0.2.7:5353" ]);
        assert!(resolver.search_list.is_empty());
    }

    #[test]
    fn names_with_several_labels_are_not_searched() {
        let resolver = Resolver { nameservers: Vec::new(), search_list: vec![ "corp.example".into() ] };
        assert_eq!(resolver.name_list(&labels("www.example")), [ labels("www.example") ]);
    }

    #[test]
    fn single_labels_are_searched_first() {
        let too_long = "a".repeat(300);
        let resolver = Resolver { nameservers: Vec::new(), search_list: vec![ "corp.example".into(), too_long, "example.org".into() ] };
        assert_eq!(resolver.name_list(&labels("printer")),
                   [ labels("printer.corp.example"), labels("printer.example.org"), labels("printer") ]);
    }
}
