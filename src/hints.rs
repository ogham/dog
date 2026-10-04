//! Hints to the user made before a query is sent, in case the answer that
//! comes back isn’t what they expect.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

use log::*;


/// The set of hostnames that are configured to point to a specific host in
/// the hosts file on the local machine. This gets queried before a request is
/// made: because the running OS will consult the hosts file before looking up
/// a hostname, but dog will not, it’s possible for dog to output one address
/// while the OS is using another. dog displays a warning when this is the
/// case, to prevent confusion.
#[derive(Default)]
pub struct LocalHosts {
    hostnames: BTreeSet<dns::Labels>,
}

impl LocalHosts {

    /// Loads the set of hostnames from the hosts file at the given path.
    pub fn load(path: &Path) -> io::Result<Self> {
        debug!("Reading hints from {}", path.display());
        Self::load_from_reader(BufReader::new(File::open(path)?))
    }

    /// Reads hostnames in the standard `/etc/hosts` format: one entry per
    /// line, separated by whitespace, where the first field is the address
    /// and the remaining fields are hostname aliases, and `#` starts a
    /// comment.
    fn load_from_reader(reader: impl BufRead) -> io::Result<Self> {
        let mut hostnames = BTreeSet::new();
        for line in reader.lines() {
            let mut line = line?;

            if let Some(hash_index) = line.find('#') {
                line.truncate(hash_index);
            }

            for hostname in line.split_ascii_whitespace().skip(1) {
                match dns::Labels::encode(hostname) {
                    Ok(hn) => {
                        hostnames.insert(hn);
                    }
                    Err(e) => {
                        warn!("Failed to encode local host hint {hostname:?}: {e}");
                    }
                }
            }
        }

        trace!("{} hostname hints loaded OK.", hostnames.len());
        Ok(Self { hostnames })
    }

    /// Queries this set of hostnames to see if the given name, which is about
    /// to be queried for, exists within the file.
    pub fn contains(&self, hostname_in_query: &dns::Labels) -> bool {
        self.hostnames.contains(hostname_in_query)
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use test_support::fixtures;

    fn names(hosts: &LocalHosts) -> Vec<String> {
        let mut names = hosts.hostnames.iter().map(ToString::to_string).collect::<Vec<_>>();
        names.sort();
        names
    }

    fn labels(name: &str) -> dns::Labels {
        dns::Labels::encode(name).unwrap()
    }

    #[test]
    fn debian_hosts_file() {
        let hosts = LocalHosts::load(&fixtures::root().join("etc/hosts.debian")).unwrap();
        assert_eq!(names(&hosts), [ "ip6-allnodes.", "ip6-allrouters.", "ip6-localhost.", "ip6-loopback.", "localhost.", "workstation.", "workstation.corp.example." ]);
        assert!(hosts.contains(&labels("localhost")));
        assert!(hosts.contains(&labels("workstation.corp.example")));
        assert!(!hosts.contains(&labels("corp.example")));

        // Case folding is part of IDNA processing, so without it a name in
        // a different case is a different name.
        assert_eq!(hosts.contains(&labels("WORKSTATION.corp.example")), cfg!(feature = "with_idna"));
    }

    #[test]
    fn docker_hosts_file() {
        let hosts = LocalHosts::load(&fixtures::root().join("etc/hosts.docker")).unwrap();
        assert!(hosts.contains(&labels("b9409679eacd")));
        assert!(hosts.contains(&labels("ip6-mcastprefix")));
        assert_eq!(hosts.hostnames.len(), 8);
    }

    #[test]
    fn comments_and_blank_lines() {
        let text = "# a comment line\n\n192.0.2.1 one.example # two.example\n   \n192.0.2.3\tthree.example\tthree\n";
        let hosts = LocalHosts::load_from_reader(text.as_bytes()).unwrap();
        assert_eq!(names(&hosts), [ "one.example.", "three.", "three.example." ]);
    }

    #[test]
    fn names_that_cannot_be_labels_are_skipped() {
        let text = format!("192.0.2.1 {} fine.example\n", "a".repeat(300));
        let hosts = LocalHosts::load_from_reader(text.as_bytes()).unwrap();
        assert_eq!(names(&hosts), [ "fine.example." ]);
    }

    #[test]
    fn invalid_utf8_is_an_error() {
        assert!(LocalHosts::load_from_reader(&b"192.0.2.1 bad\xff.example\n"[..]).is_err());
    }

    #[test]
    fn missing_file_is_an_error() {
        let error = LocalHosts::load(&fixtures::root().join("etc/no-such-file")).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
