use std::io::{self, Read, Write};
use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error, DEFAULT_TIMEOUT};
use super::{address, net};
use super::net::Deadline;


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
    timeout: Duration,
}

impl TcpTransport {

    /// Creates a new TCP transport that connects to the given host, and
    /// waits for it for the default time.
    pub fn new(addr: String) -> Self {
        Self::with_timeout(addr, DEFAULT_TIMEOUT)
    }

    /// Creates a new TCP transport that connects to the given host, and
    /// gives up if the whole exchange has not finished within `timeout`.
    pub fn with_timeout(addr: String, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}


impl Transport for TcpTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let deadline = Deadline::after(self.timeout);

        info!("Opening TCP stream");
        let (host, port) = address::parse_host_port(&self.addr, 53)?;
        let mut stream = net::connect_tcp(host, port, deadline)?;
        debug!("Opened");

        info!("Sending a request to {:?} over TCP", self.addr);
        exchange(&mut stream, request, self.timeout)
    }
}


/// Sends a request and reads its response over a stream that frames each
/// message with its length (RFC 1035 §4.2.2), as TCP and TLS both do.
/// Returns an error if the response does not answer the request.
pub(crate) fn exchange(stream: &mut (impl Read + Write), request: &Request, timeout: Duration) -> Result<Response, Error> {
    let bytes_to_send = prefix_with_length(request.to_bytes()?)?;
    stream.write_all(&bytes_to_send).and_then(|()| stream.flush()).map_err(|e| net::io_error(e, timeout))?;
    debug!("Wrote {} bytes", bytes_to_send.len());

    let read_bytes = length_prefixed_read(stream, timeout)?;
    let response = Response::from_bytes(&read_bytes)?;
    request.check_response(&response)?;
    Ok(response)
}

/// Prefixes a message with its own length, as a big-endian `u16`.
fn prefix_with_length(message: Vec<u8>) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "request too long"))?;

    let mut bytes = Vec::with_capacity(message.len() + 2);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend(message);
    Ok(bytes)
}

/// Reads one length-prefixed message: two bytes of big-endian length, then
/// that many bytes, over however many reads it takes. Anything after the
/// stated length is left unread.
///
/// # Errors
///
/// Returns `TruncatedResponse` if the stream ends early, or a network
/// error, or a timeout.
pub(crate) fn length_prefixed_read(stream: &mut impl Read, timeout: Duration) -> Result<Vec<u8>, Error> {
    info!("Waiting to receive...");
    let mut length = [0; 2];
    read_fully(stream, &mut length, timeout)?;

    let mut message = vec![0; usize::from(u16::from_be_bytes(length))];
    read_fully(stream, &mut message, timeout)?;
    info!("Received {} bytes of data", message.len());
    Ok(message)
}

/// Fills the buffer, however many reads that takes. An early end of the
/// stream means the response was cut short.
pub(crate) fn read_fully(stream: &mut impl Read, buf: &mut [u8], timeout: Duration) -> Result<(), Error> {
    stream.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            warn!("The connection closed before the whole response arrived");
            Error::TruncatedResponse
        }
        else {
            net::io_error(e, timeout)
        }
    })
}


#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;
    use crate::test_util::{a_example, SHORT};
    use test_support::{fixtures, mock, wire};

    /// A stream that reads from one buffer and writes to another.
    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A stream whose reads and writes always fail in the given way.
    struct Failing(io::ErrorKind);

    impl Read for Failing {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(self.0.into())
        }
    }

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(self.0.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn exchange_over_any_stream() {
        let response = wire::with_txid(&fixtures::response("a-example-tcp"), 0x1234);
        let mut stream = Duplex { input: Cursor::new(mock::prefixed(&response)), output: Vec::new() };

        let answer = exchange(&mut stream, &a_example(), SHORT).unwrap();
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(stream.output, mock::prefixed(&a_example().to_bytes().unwrap()));
    }

    #[test]
    fn bytes_after_the_message_are_left_unread() {
        let mut input = Cursor::new([ &[ 0, 3 ][..], b"abcdef" ].concat());
        assert_eq!(length_prefixed_read(&mut input, SHORT).unwrap(), b"abc");
        assert_eq!(input.position(), 5);
    }

    #[test]
    fn stream_failures() {
        Write::flush(&mut Failing(io::ErrorKind::Other)).unwrap();
        assert!(matches!(exchange(&mut Failing(io::ErrorKind::WouldBlock), &a_example(), SHORT), Err(Error::Timeout(SHORT))));
        assert!(matches!(exchange(&mut Failing(io::ErrorKind::BrokenPipe), &a_example(), SHORT), Err(Error::NetworkError(_))));
        assert!(matches!(length_prefixed_read(&mut Failing(io::ErrorKind::TimedOut), SHORT), Err(Error::Timeout(SHORT))));
        assert!(matches!(length_prefixed_read(&mut Failing(io::ErrorKind::ConnectionReset), SHORT), Err(Error::NetworkError(_))));
    }

    #[test]
    fn early_ends_are_truncated_responses() {
        for input in [ &[][..], &[ 0 ][..], &[ 0, 5, 1, 2 ][..] ] {
            assert!(matches!(length_prefixed_read(&mut Cursor::new(input), SHORT), Err(Error::TruncatedResponse)), "{input:?}");
        }
    }

    #[test]
    fn a_request_too_long_for_its_prefix() {
        assert!(matches!(prefix_with_length(vec![ 0; 65536 ]), Err(Error::NetworkError(_))));
        assert_eq!(prefix_with_length(vec![ 7; 3 ]).unwrap(), [ 0, 3, 7, 7, 7 ]);
    }
}
