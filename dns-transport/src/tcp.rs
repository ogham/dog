use std::convert::TryFrom;
use std::net::TcpStream;
use std::io::{Read, Write};

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};


/// The **TCP transport**, which sends DNS wire data over a TCP stream.
///
/// # Examples
///
/// ```no_run
/// use dns_transport::{Transport, TcpTransport};
/// use dns::{Request, Flags, Query, Labels, QClass, qtype, record::MX};
///
/// let query = Query {
///     qname: Labels::encode("dns.lookup.dog").unwrap(),
///     qclass: QClass::IN,
///     qtype: qtype!(MX),
/// };
///
/// let request = Request {
///     transaction_id: 0xABCD,
///     flags: Flags::query(),
///     query: query,
///     additional: None,
/// };
///
/// let transport = TcpTransport::new("8.8.8.8");
/// transport.send(&request);
/// ```
///
/// # References
///
/// - [RFC 1035 §4.2.2](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
/// - [RFC 7766](https://tools.ietf.org/html/rfc1035) — DNS Transport over
///   TCP, Implementation Requirements (March 2016)
#[derive(Debug)]
pub struct TcpTransport {
    addr: String,
}

impl TcpTransport {

    /// Creates a new TCP transport that connects to the given host.
    pub fn new(sa: impl Into<String>) -> Self {
        Self { addr: sa.into() }
    }
}


impl Transport for TcpTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let mut stream =
            if self.addr.contains(':') {
                TcpStream::connect(&*self.addr)?
            }
            else {
                TcpStream::connect((&*self.addr, 53))?
            };
        info!("Created stream");

        // The message is prepended with the length when sent over TCP,
        // so the server knows how long it is (RFC 1035 §4.2.2)
        let mut bytes = request.to_bytes().expect("failed to serialise request");
        let len_bytes = u16::try_from(bytes.len()).expect("request too long").to_be_bytes();
        bytes.insert(0, len_bytes[0]);
        bytes.insert(1, len_bytes[1]);

        info!("Sending {} bytes of data to {} over TCP", bytes.len(), self.addr);

        let written_len = stream.write(&bytes)?;
        debug!("Wrote {} bytes", written_len);

        info!("Waiting to receive...");
        let mut buf = [0; 4096];
        let mut read_len = stream.read(&mut buf[..])?;

        if read_len == 0 {
            panic!("Received no bytes!");
        }
        else if read_len == 1 {
            info!("Received one byte of data");
            let second_read_len = stream.read(&mut buf[1..])?;
            if second_read_len == 0 {
                panic!("Received no bytes the second time!");
            }

            read_len += second_read_len;
        }
        else {
            info!("Received {} bytes of data", read_len);
        }

        let total_len = u16::from_be_bytes([buf[0], buf[1]]);
        if read_len - 2 == usize::from(total_len) {
            let response = Response::from_bytes(&buf[2 .. read_len])?;
            return Ok(response);
        }

        debug!("We need to read {} bytes total", total_len);
        let mut combined_buffer = buf[2..read_len].to_vec();
        while combined_buffer.len() < usize::from(total_len) {
            let mut extend_buf = [0; 4096];
            let extend_len = stream.read(&mut extend_buf[..])?;
            info!("Received further {} bytes of data (of {})", extend_len, total_len);

            if read_len == 0 {
                panic!("Read zero bytes!");
            }

            combined_buffer.extend(&extend_buf[0 .. extend_len]);
        }

        let response = Response::from_bytes(&combined_buffer)?;
        Ok(response)
    }
}
