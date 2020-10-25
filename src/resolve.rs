use std::io;

use log::*;


/// A **resolver** is used to obtain the IP address of the server we should
/// send DNS requests to.
#[derive(PartialEq, Debug)]
pub enum Resolver {

    /// Read the list of nameservers from the system, and use that.
    SystemDefault,

    // Use a resolver specified by the user.
    Specified(Nameserver),
}

pub type Nameserver = String;


impl Resolver {
    pub fn lookup(self) -> io::Result<Option<Nameserver>> {
        match self {
            Self::Specified(ns) => {
                Ok(Some(ns))
            }

            Self::SystemDefault => {
                use std::io::{BufRead, BufReader};
                use std::fs::File;

                let f = File::open("/etc/resolv.conf")?;
                let reader = BufReader::new(f);

                let mut nameservers = Vec::new();
                for line in reader.lines() {
                    let line = line?;

                    if let Some(nameserver_str) = line.strip_prefix("nameserver ") {
                        let ip: Result<std::net::Ipv4Addr, _> = nameserver_str.parse();

                        match ip {
                            Ok(_ip) => nameservers.push(nameserver_str.into()),
                            Err(e)  => warn!("Failed to parse nameserver line {:?}: {}", line, e),
                        }
                    }
                }

                Ok(nameservers.first().cloned())
            }
        }
    }
}
