//! Where dog finds the system’s own network configuration.

use std::path::PathBuf;


/// The files dog reads to find the system’s nameserver, search list, and
/// local host names. (On Windows, the nameserver comes from the network
/// adapters instead, and only the hosts file is read.)
#[derive(Debug, Clone)]
pub struct SystemPaths {

    /// The hosts file, for warning about names that the system resolves
    /// without asking DNS.
    pub hosts: PathBuf,

    /// The resolver configuration, for finding the default nameserver.
    /// (Windows asks its network adapters instead.)
    #[cfg_attr(windows, allow(dead_code))]
    pub resolv_conf: PathBuf,
}

impl SystemPaths {

    /// The real locations of these files on this platform.
    pub fn system() -> Self {
        let hosts = if cfg!(windows) { r"C:\Windows\system32\drivers\etc\hosts" } else { "/etc/hosts" };
        Self { hosts: hosts.into(), resolv_conf: "/etc/resolv.conf".into() }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn system_paths() {
        let paths = SystemPaths::system();
        assert_eq!(paths.hosts, PathBuf::from("/etc/hosts"));
        assert_eq!(paths.resolv_conf, PathBuf::from("/etc/resolv.conf"));
    }
}
