use std::io;
use std::time::Duration;

use log::*;

use dns::{Request, Response};
use super::{Transport, Error, DEFAULT_TIMEOUT};
use super::{address, net};
use super::net::Deadline;


/// The **UDP transport**, which sends DNS wire data inside a UDP datagram.
///
/// # References
///
/// - [RFC 1035 §4.2.1](https://tools.ietf.org/html/rfc1035) — Domain Names,
///   Implementation and Specification (November 1987)
pub struct UdpTransport {
    addr: String,
    timeout: Duration,
}

impl UdpTransport {

    /// Creates a new UDP transport that sends to the given host, and waits
    /// for its answer for the default time.
    pub fn new(addr: String) -> Self {
        Self::with_timeout(addr, DEFAULT_TIMEOUT)
    }

    /// Creates a new UDP transport that sends to the given host, and waits
    /// for its answer for at most `timeout`.
    pub fn with_timeout(addr: String, timeout: Duration) -> Self {
        Self { addr, timeout }
    }
}


impl Transport for UdpTransport {
    fn send(&self, request: &Request) -> Result<Response, Error> {
        let deadline = Deadline::after(self.timeout);

        info!("Opening UDP socket");
        let (host, port) = address::parse_host_port(&self.addr, 53)?;
        let socket = net::connect_udp(host, port, deadline)?;
        debug!("Opened");

        let bytes_to_send = request.to_bytes()?;

        info!("Sending {} bytes of data to {} over UDP", bytes_to_send.len(), self.addr);
        let written_len = socket.send(&bytes_to_send).map_err(|e| net::io_error(e, self.timeout))?;
        debug!("Wrote {written_len} bytes");

        receive(request, deadline, |buf, left| {
            socket.set_read_timeout(Some(left))?;
            socket.recv(buf)
        })
    }
}

/// Waits for the answer to the request, skipping any datagram that is not
/// it, such as a late answer to an earlier query or a forgery, until the
/// deadline. `recv` reads one datagram, waiting at most the time given.
/// A wait that is interrupted, as when dog is stopped and continued, goes
/// on with the time that is left.
fn receive(request: &Request, deadline: Deadline, mut recv: impl FnMut(&mut [u8], Duration) -> io::Result<usize>) -> Result<Response, Error> {
    info!("Waiting to receive...");

    // The largest datagram there can be, since dog lets users advertise
    // any buffer size up to that.
    let mut buf = vec![0; 65535];

    loop {
        match recv(&mut buf, deadline.left()?) {
            Ok(received_len) => {
                info!("Received {received_len} bytes of data");
                if let Some(response) = accept(request, &buf[.. received_len])? {
                    return Ok(response);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => debug!("The wait was interrupted; waiting again"),
            Err(e) => return Err(net::io_error(e, deadline.timeout())),
        }
    }
}

/// What to make of one datagram: the answer; `None` if it does not answer
/// the request, so dog should keep waiting; or an error if it carries the
/// request’s ID but cannot be read.
fn accept(request: &Request, datagram: &[u8]) -> Result<Option<Response>, Error> {
    match Response::from_bytes(datagram) {
        Ok(response) => match request.check_response(&response) {
            Ok(()) => Ok(Some(response)),
            Err(mismatch) => {
                warn!("Ignoring a datagram that does not answer the query: {mismatch}");
                Ok(None)
            }
        },
        Err(e) if carries_txid(datagram, request.transaction_id) => Err(e.into()),
        Err(e) => {
            warn!("Ignoring a datagram that cannot be read: {e:?}");
            Ok(None)
        }
    }
}

fn carries_txid(datagram: &[u8], txid: u16) -> bool {
    datagram.get(.. 2) == Some(&txid.to_be_bytes()[..])
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::test_util::{a_example, SHORT};
    use test_support::{fixtures, wire};

    #[test]
    fn the_answer_is_accepted() {
        let datagram = wire::with_txid(&fixtures::response("a-example"), 0x1234);
        assert!(accept(&a_example(), &datagram).unwrap().is_some());
    }

    #[test]
    fn other_answers_are_skipped() {
        let wrong_id = wire::with_txid(&fixtures::response("a-example"), 0x4321);
        let wrong_question = wire::with_txid(&fixtures::response("aaaa-example"), 0x1234);
        let a_query = wire::without_flag(&wire::with_txid(&fixtures::response("a-example"), 0x1234), wire::QR);

        for datagram in [ wrong_id, wrong_question, a_query ] {
            assert!(accept(&a_example(), &datagram).unwrap().is_none());
        }
    }

    #[test]
    fn unreadable_datagrams() {
        let real = wire::with_txid(&fixtures::response("a-example"), 0x1234);

        // Cut short but carrying the right ID: this is the answer, and it’s broken.
        assert!(matches!(accept(&a_example(), &real[.. 20]), Err(Error::WireError(dns::WireError::IO))));

        // Carrying some other ID, or too short to carry one: just noise.
        assert!(accept(&a_example(), &wire::with_txid(&real[.. 20], 0x4321)).unwrap().is_none());
        assert!(accept(&a_example(), &[ 0x12 ]).unwrap().is_none());
    }

    /// Plays back datagrams, or errors, one per wait, recording how long each
    /// wait was allowed to take.
    fn scripted(results: Vec<io::Result<Vec<u8>>>, waits: &mut Vec<Duration>) -> impl FnMut(&mut [u8], Duration) -> io::Result<usize> + '_ {
        let mut results = results.into_iter();
        move |buf, left| {
            waits.push(left);
            let datagram = results.next().expect("a scripted datagram")?;
            buf[.. datagram.len()].copy_from_slice(&datagram);
            Ok(datagram.len())
        }
    }

    /// Stopping dog with ^Z and continuing it interrupts the wait; before,
    /// that ended the query with “Interrupted system call”.
    #[test]
    fn an_interrupted_wait_goes_on_with_the_time_left() {
        let answer = wire::with_txid(&fixtures::response("a-example"), 0x1234);
        let noise = wire::with_txid(&answer, 0x4321);
        let mut waits = Vec::new();
        let results = vec![ Err(io::ErrorKind::Interrupted.into()), Ok(noise), Err(io::ErrorKind::Interrupted.into()), Ok(answer) ];

        let response = receive(&a_example(), Deadline::after(SHORT), scripted(results, &mut waits)).unwrap();
        assert_eq!(response.answers.len(), 1);
        assert_eq!(waits.len(), 4);
        assert!(waits.windows(2).all(|pair| pair[1] <= pair[0] && pair[0] <= SHORT), "{waits:?}");
    }

    #[test]
    fn waits_that_fail() {
        let mut waits = Vec::new();
        let timed_out = receive(&a_example(), Deadline::after(SHORT), scripted(vec![ Err(io::ErrorKind::WouldBlock.into()) ], &mut waits));
        assert!(matches!(timed_out, Err(Error::Timeout(SHORT))), "{timed_out:?}");

        let refused = receive(&a_example(), Deadline::after(SHORT), scripted(vec![ Err(io::ErrorKind::ConnectionRefused.into()) ], &mut waits));
        assert!(matches!(refused, Err(Error::NetworkError(_))), "{refused:?}");

        let expired = receive(&a_example(), Deadline::after(Duration::ZERO), scripted(Vec::new(), &mut waits));
        assert!(matches!(expired, Err(Error::Timeout(_))), "{expired:?}");
    }
}
