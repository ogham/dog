//! Socket plumbing shared by the transports: finding a server’s addresses,
//! connecting to it, and reading and writing, all before one deadline, and
//! telling a timeout from any other failure.

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use log::*;

use super::Error;


/// The moment by which a whole exchange with a server must be over. Finding
/// the server’s addresses, connecting, sending, and every read of the answer
/// all count towards it, so a server that trickles its answer out a byte at
/// a time cannot keep dog waiting any longer than one that says nothing.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Deadline {
    at: Instant,
    timeout: Duration,
}

impl Deadline {

    /// A deadline `timeout` from now.
    pub(crate) fn after(timeout: Duration) -> Self {
        Self { at: Instant::now() + timeout, timeout }
    }

    /// The time limit the deadline was set with, for error messages.
    pub(crate) fn timeout(self) -> Duration {
        self.timeout
    }

    /// How long is left, or a timeout if the deadline has passed.
    pub(crate) fn left(self) -> Result<Duration, Error> {
        self.io_left().map_err(|_| Error::Timeout(self.timeout))
    }

    /// How long is left or, once the deadline has passed, the error a socket
    /// gives when its own timeout runs out, so that the two are handled alike.
    fn io_left(self) -> io::Result<Duration> {
        let left = self.at.saturating_duration_since(Instant::now());
        if left.is_zero() { Err(io::ErrorKind::WouldBlock.into()) } else { Ok(left) }
    }
}


/// Finds the addresses of a host, which may be an IP address or a name.
pub(crate) fn addresses(host: &str, port: u16, deadline: Deadline) -> Result<Vec<SocketAddr>, Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ SocketAddr::new(ip, port) ]);
    }

    let host = host.to_owned();
    lookup_before(deadline, move || (host.as_str(), port).to_socket_addrs().map(Iterator::collect))
}

/// Runs a name lookup on a thread of its own, because the system’s resolver
/// can take as long as it likes, and waits for it only until the deadline.
/// A lookup still running then is left to finish by itself, unheeded.
fn lookup_before<F>(deadline: Deadline, lookup: F) -> Result<Vec<SocketAddr>, Error>
where F: FnOnce() -> io::Result<Vec<SocketAddr>> + Send + 'static
{
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        if sender.send(lookup()).is_err() {
            debug!("A name lookup finished after dog had stopped waiting for it");
        }
    });

    match receiver.recv_timeout(deadline.left()?) {
        Ok(result) => Ok(result?),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(Error::Timeout(deadline.timeout)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other("the name lookup stopped without an answer").into()),
    }
}


/// Connects to the first of the host’s addresses that accepts a connection,
/// all before the deadline, and returns a stream that keeps to it.
pub(crate) fn connect_tcp(host: &str, port: u16, deadline: Deadline) -> Result<DeadlineStream<TcpStream>, Error> {
    let mut last_error = no_addresses(host);
    for addr in addresses(host, port, deadline)? {
        match TcpStream::connect_timeout(&addr, deadline.left()?) {
            Ok(stream) => return configure(stream, deadline),
            Err(e) => {
                debug!("Could not connect to {addr}: {e}");
                last_error = e;
            }
        }
    }

    Err(io_error(last_error, deadline.timeout))
}

fn configure(stream: TcpStream, deadline: Deadline) -> Result<DeadlineStream<TcpStream>, Error> {
    // dog writes each message whole, so holding back small writes to join
    // them up gains nothing, and costs a round trip in the TLS handshake.
    stream.set_nodelay(true)?;
    Ok(DeadlineStream::new(stream, deadline))
}

/// Opens a UDP socket connected to the first of the host’s addresses that it
/// can be connected to, bound to a local address of the same family.
pub(crate) fn connect_udp(host: &str, port: u16, deadline: Deadline) -> Result<UdpSocket, Error> {
    let mut last_error = no_addresses(host);
    for addr in addresses(host, port, deadline)? {
        match open_udp(addr) {
            Ok(socket) => return Ok(socket),
            Err(e) => {
                debug!("Could not use {addr}: {e}");
                last_error = e;
            }
        }
    }

    Err(io_error(last_error, deadline.timeout))
}

fn open_udp(server: SocketAddr) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(local_address_for(server))?;
    socket.connect(server)?;
    Ok(socket)
}

/// Any local address, on any port, of the same family as the server’s.
fn local_address_for(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() }
}

fn no_addresses(host: &str) -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, format!("{host} has no addresses"))
}


/// A socket whose reads and writes can be given time limits.
pub(crate) trait Timeouts {

    /// Limits how long each read can wait.
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;

    /// Limits how long each write can wait.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Timeouts for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_write_timeout(self, timeout)
    }
}

/// A stream on which every read and write has to be over by the deadline:
/// before each one, the socket’s timeout is set to whatever time is left,
/// rather than to the whole timeout afresh.
///
/// A read or write that is interrupted, as happens when dog is stopped and
/// continued, is tried again with the time that is left, instead of failing.
#[derive(Debug)]
pub(crate) struct DeadlineStream<S> {
    stream: S,
    deadline: Deadline,
}

impl<S> DeadlineStream<S> {
    pub(crate) fn new(stream: S, deadline: Deadline) -> Self {
        Self { stream, deadline }
    }
}

impl<S: Read + Timeouts> Read for DeadlineStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            self.stream.set_read_timeout(Some(self.deadline.io_left()?))?;
            match self.stream.read(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => debug!("A read was interrupted; trying again"),
                result => return result,
            }
        }
    }
}

impl<S: Write + Timeouts> Write for DeadlineStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        loop {
            self.stream.set_write_timeout(Some(self.deadline.io_left()?))?;
            match self.stream.write(buf) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => debug!("A write was interrupted; trying again"),
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}


/// Turns an I/O error into a transport error, recognising both of the ways
/// a socket reports that its timeout ran out.
pub(crate) fn io_error(error: io::Error, timeout: Duration) -> Error {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Error::Timeout(timeout),
        _ => Error::NetworkError(error),
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::TcpListener;

    const TIMEOUT: Duration = Duration::from_millis(300);

    fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    fn expired() -> Deadline {
        Deadline::after(Duration::ZERO)
    }

    #[test]
    fn timeouts_are_recognised() {
        assert!(matches!(io_error(io::ErrorKind::WouldBlock.into(), TIMEOUT), Error::Timeout(TIMEOUT)));
        assert!(matches!(io_error(io::ErrorKind::TimedOut.into(), TIMEOUT), Error::Timeout(TIMEOUT)));
        assert!(matches!(io_error(io::ErrorKind::ConnectionReset.into(), TIMEOUT), Error::NetworkError(_)));
    }

    #[test]
    fn deadlines() {
        let deadline = Deadline::after(TIMEOUT);
        assert!(deadline.left().unwrap() <= TIMEOUT);
        assert_eq!(deadline.timeout(), TIMEOUT);
        assert!(matches!(expired().left(), Err(Error::Timeout(Duration::ZERO))));
        assert_eq!(expired().io_left().unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn connecting_to_a_listening_port() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = connect_tcp("127.0.0.1", listener.local_addr().unwrap().port(), Deadline::after(TIMEOUT)).unwrap();
        assert!(stream.stream.nodelay().unwrap());
    }

    #[test]
    fn connecting_to_a_closed_port() {
        let error = connect_tcp("127.0.0.1", closed_port(), Deadline::after(TIMEOUT)).unwrap_err();
        assert!(matches!(&error, Error::NetworkError(e) if e.kind() == io::ErrorKind::ConnectionRefused), "{error:?}");
    }

    /// A deadline that has passed stops dog from trying any more addresses.
    #[test]
    fn connecting_after_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(matches!(connect_tcp("127.0.0.1", port, expired()), Err(Error::Timeout(_))));
        assert!(matches!(connect_udp("localhost", 53, expired()), Err(Error::Timeout(_))));
    }

    #[test]
    fn udp_sockets_are_connected_to_the_server() {
        let socket = connect_udp("127.0.0.1", 53, Deadline::after(TIMEOUT)).unwrap();
        assert_eq!(socket.peer_addr().unwrap(), "127.0.0.1:53".parse().unwrap());
        assert!(socket.local_addr().unwrap().is_ipv4());
    }

    #[test]
    fn local_addresses_match_the_server_family() {
        assert_eq!(local_address_for("192.0.2.1:53".parse().unwrap()), "0.0.0.0:0".parse().unwrap());
        assert_eq!(local_address_for("[2001:db8::1]:53".parse().unwrap()), "[::]:0".parse().unwrap());
    }

    #[test]
    fn unusable_udp_addresses() {
        // Sending to the broadcast address needs a permission (SO_BROADCAST)
        // that a DNS client has no business asking for.
        assert!(matches!(connect_udp("255.255.255.255", 53, Deadline::after(TIMEOUT)), Err(Error::NetworkError(_))));
    }

    #[test]
    fn a_host_with_no_addresses() {
        assert_eq!(no_addresses("nowhere").to_string(), "nowhere has no addresses");
    }

    #[test]
    fn addresses_of_ips_and_names() {
        let deadline = Deadline::after(TIMEOUT * 10);
        assert_eq!(addresses("192.0.2.1", 53, deadline).unwrap(), [ "192.0.2.1:53".parse().unwrap() ]);
        assert_eq!(addresses("::1", 853, deadline).unwrap(), [ "[::1]:853".parse().unwrap() ]);
        assert!(addresses("localhost", 53, deadline).unwrap().iter().all(|addr| addr.ip().is_loopback() && addr.port() == 53));
    }

    /// The system’s resolver can hang for far longer than dog’s timeout, as
    /// it did for ten seconds on a name that did not exist.
    #[test]
    fn a_slow_lookup_times_out() {
        let started = Instant::now();
        let result = lookup_before(Deadline::after(TIMEOUT), || {
            thread::sleep(TIMEOUT * 4);
            Ok(Vec::new())
        });
        assert!(matches!(result, Err(Error::Timeout(TIMEOUT))), "{result:?}");
        assert!(started.elapsed() < TIMEOUT * 3, "{:?}", started.elapsed());
    }

    #[test]
    fn lookup_failures() {
        let deadline = Deadline::after(TIMEOUT);
        assert!(matches!(lookup_before(deadline, || Err(io::Error::other("no such host"))), Err(Error::NetworkError(_))));
        assert!(matches!(lookup_before(deadline, || panic!("the lookup thread died")), Err(Error::NetworkError(_))));
        assert!(matches!(lookup_before(expired(), || Ok(Vec::new())), Err(Error::Timeout(_))));
    }

    /// A stream that plays back some results, and records the timeouts set
    /// on it before each read or write.
    struct Scripted {
        results: RefCell<VecDeque<io::Result<usize>>>,
        timeouts: RefCell<Vec<Duration>>,
    }

    impl Scripted {
        fn new(results: Vec<io::Result<usize>>) -> Self {
            Self { results: RefCell::new(results.into()), timeouts: RefCell::new(Vec::new()) }
        }

        fn next(&self) -> io::Result<usize> {
            self.results.borrow_mut().pop_front().expect("a scripted result")
        }
    }

    impl Timeouts for Scripted {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.timeouts.borrow_mut().push(timeout.unwrap());
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.set_read_timeout(timeout)
        }
    }

    impl Read for Scripted {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            self.next()
        }
    }

    impl Write for Scripted {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.next()
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Stopping dog with ^Z and continuing it interrupts whatever it was
    /// waiting for; before, that ended the query with an error.
    #[test]
    fn interrupted_reads_and_writes_are_retried_with_the_time_left() {
        let interrupted = || Err(io::ErrorKind::Interrupted.into());
        let scripted = Scripted::new(vec![ interrupted(), Ok(3), interrupted(), interrupted(), Ok(2) ]);
        let mut stream = DeadlineStream::new(scripted, Deadline::after(TIMEOUT));

        assert_eq!(stream.read(&mut [0; 8]).unwrap(), 3);
        assert_eq!(stream.write(b"ab").unwrap(), 2);
        stream.flush().unwrap();

        let timeouts = stream.stream.timeouts.borrow();
        assert_eq!(timeouts.len(), 5);
        assert!(timeouts.windows(2).all(|pair| pair[1] <= pair[0] && pair[0] <= TIMEOUT), "{timeouts:?}");
    }

    #[test]
    fn nothing_is_read_or_written_after_the_deadline() {
        let mut stream = DeadlineStream::new(Scripted::new(Vec::new()), expired());
        assert_eq!(stream.read(&mut [0; 8]).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert_eq!(stream.write(b"ab").unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn other_failures_are_returned() {
        let mut stream = DeadlineStream::new(Scripted::new(vec![ Err(io::ErrorKind::ConnectionReset.into()) ]), Deadline::after(TIMEOUT));
        assert_eq!(stream.read(&mut [0; 8]).unwrap_err().kind(), io::ErrorKind::ConnectionReset);
    }
}
