//! Specifying the address of the DNS server to send requests to.

use std::io;

use log::*;


/// A **resolver** is used to obtain the IP address of the server we should
/// send DNS requests to.
#[derive(PartialEq, Debug)]
pub enum Resolver {

    /// Read the list of nameservers from the system, and use that.
    SystemDefault,

    // Use a specific nameserver specified by the user.
    Specified(Nameserver),
}

pub type Nameserver = String;

impl Resolver {

    /// Returns a nameserver that queries should be sent to, possibly by
    /// obtaining one based on the system, returning an error if there was a
    /// problem looking one up.
    pub fn lookup(self) -> io::Result<Option<Nameserver>> {
        match self {
            Self::Specified(ns)  => Ok(Some(ns)),
            Self::SystemDefault  => system_nameservers(),
        }
    }
}


/// Looks up the system default nameserver on Unix, by querying
/// `/etc/resolv.conf` and returning the first line that specifies one.
/// Returns an error if there’s a problem reading the file, or `None` if no
/// nameserver is specified in the file.
#[cfg(unix)]
fn system_nameservers() -> io::Result<Option<Nameserver>> {
    use std::io::{BufRead, BufReader};
    use std::fs::File;

    let f = File::open("/etc/resolv.conf")?;
    let reader = BufReader::new(f);

    let mut nameservers = Vec::new();
    for line in reader.lines() {
        let line = line?;

        if let Some(nameserver_str) = line.strip_prefix("nameserver ") {
            let ip: Result<std::net::Ipv4Addr, _> = nameserver_str.parse();
            // TODO: This will need to be changed for IPv6 support.

            match ip {
                Ok(_ip) => nameservers.push(nameserver_str.into()),
                Err(e)  => warn!("Failed to parse nameserver line {:?}: {}", line, e),
            }
        }
    }

    Ok(nameservers.first().cloned())
}


/// Looks up the system default nameserver on Windows, by iterating through
/// the list of network adapters and returning the first nameserver it finds.
#[cfg(windows)]
fn system_nameservers() -> io::Result<Option<Nameserver>> {
    let adapters = match ipconfig::get_adapters() {
        Ok(a) => a,
        Err(e) => {
            warn!("Error getting network adapters: {}", e);
            return Ok(None);
        }
    };

    for dns_server in adapters
        .iter()
        .flat_map(|adapter| adapter.dns_servers().iter()) {
            // TODO: This will need to be changed for IPv6 support.
            if dns_server.is_ipv4() {
                debug!("Found first nameserver {:?}", dns_server);
                return Ok(Some(dns_server.to_string()))
            }
    }

    warn!("No nameservers available");
    return Ok(None)
}


/// The fall-back system default nameserver determinator that is not very
/// determined as it returns nothing without actually checking anything.
#[cfg(all(not(unix), not(windows)))]
fn system_nameservers() -> io::Result<Option<Nameserver>> {
    warn!("Unable to fetch default nameservers on this platform.");
    Ok(None)
}
