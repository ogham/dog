//! Hints to the user made before a query is sent, in case the answer that
//! comes back isn’t what they expect.

use std::collections::BTreeSet;
use std::fs::File;
use std::io;

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

    /// Loads the set of hostnames from the hosts file path on Unix.
    #[cfg(unix)]
    pub fn load() -> io::Result<Self> {
        debug!("Reading hints from /etc/hosts");
        Self::load_from_file(File::open("/etc/hosts")?)
    }

    /// Loads the set of hostnames from the hosts file path on Windows.
    #[cfg(windows)]
    pub fn load() -> io::Result<Self> {
        debug!("Reading hints from /etc/hosts equivalent");
        Self::load_from_file(File::open("C:\\Windows\\system32\\drivers\\etc\\hosts")?)
    }

    /// On other machines, load an empty set of hostnames that match nothing.
    #[cfg(all(not(windows), not(unix)))]
    pub fn load() -> io::Result<Self> {
        Ok(Self::default())
    }

    /// Reads hostnames from the given file and returns them as a `LocalHosts`
    /// struct, or an I/O error if one occurs. The file should be in the
    /// standard `/etc/hosts` format, with one entry per line, separated by
    /// whitespace, where the first field is the address and the remaining
    /// fields are hostname aliases, and `#` signifies a comment.
    fn load_from_file(file: File) -> io::Result<Self> {
        use std::io::{BufRead, BufReader};

        if cfg!(test) {
            panic!("load_from_file() called from test code");
        }

        let reader = BufReader::new(file);

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
                        warn!("Failed to encode local host hint {:?}: {}", hostname, e);
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
