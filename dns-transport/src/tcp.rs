use std::convert::TryFrom;
use std::net::TcpStream;
use std::io::{Read, Write};
use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error};
use super::to_socket_addr;

/// The **TCP transport**, which sends DNS wire data over a TCP stream.
///
/// # References
///
/// - [RFC 1035 §4.2.2](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
/// - [RFC 7766](https://tools.ietf.org/html/rfc1035) — DNS Transport over
///   TCP, Implementation Requirements (March 2016)
pub struct TcpTransport {
    addr: String,
}

impl TcpTransport {

    /// Creates a new TCP transport that connects to the given host.
    pub fn new(addr: String) -> Self {
        Self { addr }
    }
}

impl Transport for TcpTransport {
    fn send(&self, request: &Request, timeout: Option<Duration>) -> Result<Response, Error> {
        info!("Opening TCP stream");

        let sock_addr = match to_socket_addr(&self.addr, 53) {
            Ok(addr) => addr,
            Err(e) => return Err(e),
        };
        let mut stream = if timeout.is_none() {
            TcpStream::connect(&sock_addr)?
        } else {
            TcpStream::connect_timeout(&sock_addr, timeout.unwrap())?
        };
        debug!("Opened");

        // The message is prepended with the length when sent over TCP,
        // so the server knows how long it is (RFC 1035 §4.2.2)
        let mut bytes_to_send = request.to_bytes().expect("failed to serialise request");
        Self::prefix_with_length(&mut bytes_to_send);

        info!("Sending {} bytes of data to {:?} over TCP", bytes_to_send.len(), self.addr);
        let written_len = stream.write(&bytes_to_send)?;
        debug!("Wrote {} bytes", written_len);

        let read_bytes = Self::length_prefixed_read(&mut stream)?;
        let response = Response::from_bytes(&read_bytes)?;
        Ok(response)
    }
}

impl TcpTransport {

    /// Mutate the given byte buffer, prefixing it with its own length as a
    /// big-endian `u16`.
    pub(crate) fn prefix_with_length(bytes: &mut Vec<u8>) {
        let len_bytes = u16::try_from(bytes.len())
            .expect("request too long")
            .to_be_bytes();

        bytes.insert(0, len_bytes[0]);
        bytes.insert(1, len_bytes[1]);
    }

    /// Reads from the given I/O source as many times as necessary to read a
    /// length-prefixed stream of bytes. The first two bytes are taken as a
    /// big-endian `u16` to determine the length. Then, that many bytes are
    /// read from the source.
    ///
    /// # Errors
    ///
    /// Returns an error if there’s a network error during reading, or not
    /// enough bytes have been sent.
    pub(crate) fn length_prefixed_read(stream: &mut impl Read) -> Result<Vec<u8>, Error> {
        info!("Waiting to receive...");

        let mut buf = [0; 4096];
        let mut read_len = stream.read(&mut buf[..])?;

        if read_len == 0 {
            warn!("Received no bytes!");
            return Err(Error::TruncatedResponse);
        }
        else if read_len == 1 {
            info!("Received one byte of data");
            let second_read_len = stream.read(&mut buf[1..])?;
            if second_read_len == 0 {
                warn!("Received no bytes the second time!");
                return Err(Error::TruncatedResponse);
            }

            read_len += second_read_len;
        }
        else {
            info!("Received {} bytes of data", read_len);
        }

        let total_len = u16::from_be_bytes([buf[0], buf[1]]);
        if read_len - 2 == usize::from(total_len) {
            debug!("We have enough bytes");
            return Ok(buf[2..read_len].to_vec());
        }

        debug!("We need to read {} bytes total", total_len);
        let mut combined_buffer = buf[2..read_len].to_vec();
        while combined_buffer.len() < usize::from(total_len) {
            let mut extend_buf = [0; 4096];
            let extend_len = stream.read(&mut extend_buf[..])?;
            info!("Received further {} bytes of data (of {})", extend_len, total_len);

            if extend_len == 0 {
                warn!("Read zero bytes!");
                return Err(Error::TruncatedResponse);
            }

            combined_buffer.extend(&extend_buf[0 .. extend_len]);
        }

        Ok(combined_buffer)
    }
}
