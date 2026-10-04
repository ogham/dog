//! Creating DNS transports based on the user’s input arguments.

use std::time::Duration;

use dns_transport::*;


/// A **transport type** creates a `Transport` that determines which protocols
/// should be used to send and receive DNS wire data over the network.
///
/// The encrypted transports only exist when dog is compiled with them; the
/// options parser refuses `--tls` and `--https` otherwise.
#[derive(PartialEq, Debug, Copy, Clone)]
pub enum TransportType {

    /// Send packets over UDP or TCP.
    /// UDP is used by default. If the request packet would be too large, send
    /// a TCP packet instead; if a UDP _response_ packet is truncated, try
    /// again with TCP.
    Automatic,

    /// Send packets over UDP only.
    /// If the request packet is too large or the response packet is
    /// truncated, fail with an error.
    UDP,

    /// Send packets over TCP only.
    TCP,

    /// Send encrypted DNS-over-TLS packets.
    #[cfg(feature = "with_tls")]
    TLS,

    /// Send encrypted DNS-over-HTTPS packets.
    #[cfg(feature = "with_https")]
    HTTPS,
}

impl TransportType {

    /// Creates a boxed `Transport` depending on the transport type. The
    /// parameter will be a URL for the HTTPS transport type, and a
    /// stringified address for the others. It waits up to `timeout` for the
    /// nameserver, first to accept a connection and then to answer.
    pub fn make_transport(self, param: String, timeout: Duration) -> Box<dyn Transport> {
        match self {
            Self::Automatic  => Box::new(AutoTransport::with_timeout(param, timeout)),
            Self::UDP        => Box::new(UdpTransport::with_timeout(param, timeout)),
            Self::TCP        => Box::new(TcpTransport::with_timeout(param, timeout)),
            #[cfg(feature = "with_tls")]
            Self::TLS        => Box::new(TlsTransport::with_timeout(param, timeout)),
            #[cfg(feature = "with_https")]
            Self::HTTPS      => Box::new(HttpsTransport::with_timeout(param, timeout)),
        }
    }

    /// Creates a transport that sends to the first of the nameservers, and
    /// on to the next whenever one fails to answer, each within `timeout`.
    pub fn make_transport_to(self, nameservers: &[String], timeout: Duration) -> Box<dyn Transport> {
        if let [ nameserver ] = nameservers {
            return self.make_transport(nameserver.clone(), timeout);
        }

        Box::new(FailoverTransport::new(nameservers.iter().map(|nameserver| self.make_transport(nameserver.clone(), timeout)).collect()))
    }

    /// Checks that a nameserver given on the command line can be used with
    /// this transport: an address with an optional port, or for HTTPS, a
    /// URL. This lets dog reject a bad one before sending anything.
    pub fn check_nameserver(self, nameserver: &str) -> Result<(), InvalidAddress> {
        match self {
            Self::Automatic | Self::UDP | Self::TCP  => parse_host_port(nameserver, 53).map(drop),
            #[cfg(feature = "with_tls")]
            Self::TLS                                => parse_host_port(nameserver, 853).map(drop),
            #[cfg(feature = "with_https")]
            Self::HTTPS                              => parse_https_url(nameserver).map(drop),
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net::UdpSocket;
    use test_support::fixtures;
    use test_support::mock::{self, Udp};

    fn a_example() -> dns::Request {
        dns::Request {
            transaction_id: 0x1234,
            flags: dns::Flags::query(),
            query: dns::Query {
                qname: dns::Labels::encode("a-example.lookup.dog").unwrap(),
                qtype: dns::record::RecordType::A,
                qclass: dns::QClass::IN,
            },
            additional: Some(dns::Request::additional_record()),
        }
    }

    fn closed_port() -> String {
        UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().to_string()
    }

    /// The system’s nameservers are tried in turn; before, only the first
    /// was ever used, and if it was down, so was dog.
    #[test]
    fn nameservers_are_tried_in_turn() {
        let working = mock::udp(Udp::Replay(fixtures::response("a-example")));
        let transport = TransportType::UDP.make_transport_to(&[ closed_port(), working.addr().to_string() ], DEFAULT_TIMEOUT);
        assert_eq!(transport.send(&a_example()).unwrap().answers.len(), 1);
        assert_eq!(working.requests().len(), 1);
    }

    #[test]
    fn one_nameserver_is_used_alone() {
        let transport = TransportType::UDP.make_transport_to(&[ closed_port() ], DEFAULT_TIMEOUT);
        assert!(matches!(transport.send(&a_example()), Err(Error::NetworkError(_))));
    }

    #[test]
    fn nameservers() {
        assert!(TransportType::Automatic.check_nameserver("1.1.1.1").is_ok());
        assert!(TransportType::UDP.check_nameserver("[::1]:5353").is_ok());
        assert!(TransportType::TCP.check_nameserver("dns.google:53").is_ok());
        assert!(TransportType::TCP.check_nameserver("dns.google:tcp").is_err());
    }

    #[cfg(feature = "with_tls")]
    #[test]
    fn tls_nameservers() {
        assert!(TransportType::TLS.check_nameserver("1.1.1.1:853").is_ok());
        assert!(TransportType::TLS.check_nameserver("1.1.1.1:").is_err());
    }

    #[cfg(feature = "with_https")]
    #[test]
    fn https_nameservers() {
        assert!(TransportType::HTTPS.check_nameserver("https://dns.google/dns-query").is_ok());
        assert!(TransportType::HTTPS.check_nameserver("dns.google").is_err());
    }
}
