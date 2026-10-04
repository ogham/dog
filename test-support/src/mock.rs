//! Loopback DNS, DNS-over-TCP and HTTP servers for tests.
//!
//! Each server binds an ephemeral port on 127.0.0.1, serves on its own
//! thread, and records every request it receives, so tests can assert on
//! exactly what dog sent. Replies are real captured fixtures. The request’s
//! transaction ID is copied into each reply, unless a mode deliberately
//! sends a wrong one.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use crate::wire;

/// How long a server waits on an idle client before giving up on it.
pub const IDLE: Duration = Duration::from_secs(30);

/// The requests a server has received, in arrival order.
pub(crate) type Log = Arc<Mutex<Vec<Vec<u8>>>>;

/// A running mock server.
#[derive(Debug)]
pub struct Server {
    addr: SocketAddr,
    log: Log,
}

impl Server {

    /// The address the server is listening on.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port the server is listening on.
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// dog’s nameserver argument for this server, such as `@127.0.0.1:41000`.
    pub fn at(&self) -> String {
        format!("@{}", self.addr)
    }

    /// Every request received so far.
    pub fn requests(&self) -> Vec<Vec<u8>> {
        lock(&self.log).clone()
    }
}

fn lock(log: &Log) -> MutexGuard<'_, Vec<Vec<u8>>> {
    // A panicking server thread must not hide what it received before that.
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn record(log: &Log, request: &[u8]) {
    lock(log).push(request.to_vec());
}

fn request_txid(query: &[u8]) -> u16 {
    if query.len() >= 2 { wire::txid(query) } else { 0 }
}


// ---- UDP ----

/// What a UDP server does with each query it receives.
#[derive(Debug, Clone)]
pub enum Udp {

    /// Reply with this response, carrying the query’s transaction ID.
    Replay(Vec<u8>),

    /// Reply with this response, carrying the query’s transaction ID, after
    /// waiting this long.
    After(Duration, Vec<u8>),

    /// Reply first with a wrong transaction ID, then with the right one.
    WrongTxidThen(Vec<u8>),

    /// Only ever reply with a wrong transaction ID.
    OnlyWrongTxid(Vec<u8>),

    /// Reply with the QR bit cleared, so the reply claims to be a query.
    NotAResponse(Vec<u8>),

    /// Reply with this response’s header and records, but with the query’s
    /// question in place of its own, so that it answers whatever was asked.
    /// Only for responses whose records point at nothing but the question,
    /// such as a lone A record.
    Echo(Vec<u8>),

    /// Send exactly these bytes, untouched.
    Raw(Vec<u8>),

    /// Send these bytes with the query’s transaction ID over the first two.
    RawWithTxid(Vec<u8>),

    /// Never reply.
    Silent,
}

impl Udp {
    fn replies(&self, query: &[u8]) -> Vec<Vec<u8>> {
        let id = request_txid(query);
        match self {
            Self::Replay(reply)         => vec![ wire::with_txid(reply, id) ],
            Self::After(_, reply)       => vec![ wire::with_txid(reply, id) ],
            Self::WrongTxidThen(reply)  => vec![ wire::with_txid(reply, id.wrapping_add(1)), wire::with_txid(reply, id) ],
            Self::OnlyWrongTxid(reply)  => vec![ wire::with_txid(reply, id.wrapping_add(1)) ],
            Self::NotAResponse(reply)   => vec![ wire::without_flag(&wire::with_txid(reply, id), wire::QR) ],
            Self::Echo(reply)           => vec![ echo(reply, query) ],
            Self::Raw(bytes)            => vec![ bytes.clone() ],
            Self::RawWithTxid(bytes)    => vec![ overwrite_txid(bytes, id) ],
            Self::Silent                => Vec::new(),
        }
    }
}

/// The reply with the query’s transaction ID and question in place of its own.
fn echo(reply: &[u8], query: &[u8]) -> Vec<u8> {
    let mut out = wire::with_txid(&reply[.. wire::HEADER_LEN], request_txid(query));
    out.extend_from_slice(&query[wire::HEADER_LEN .. wire::question_end(query)]);
    out.extend_from_slice(&reply[wire::question_end(reply) ..]);
    out
}

fn overwrite_txid(bytes: &[u8], id: u16) -> Vec<u8> {
    if bytes.len() >= 2 { wire::with_txid(bytes, id) } else { bytes.to_vec() }
}

/// Starts a UDP server on an ephemeral loopback port.
///
/// # Panics
///
/// Panics if the socket cannot be bound.
pub fn udp(mode: Udp) -> Server {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind a loopback UDP socket");
    serve_udp(socket, mode)
}

fn serve_udp(socket: UdpSocket, mode: Udp) -> Server {
    let addr = socket.local_addr().expect("the UDP socket has a local address");
    socket.set_read_timeout(Some(IDLE)).expect("set the UDP read timeout");
    let log = Log::default();
    let thread_log = Arc::clone(&log);
    thread::spawn(move || udp_loop(&socket, &mode, &thread_log));
    Server { addr, log }
}

fn udp_loop(socket: &UdpSocket, mode: &Udp, log: &Log) {
    let mut buf = vec![0; 65535];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(e) if is_timeout(&e) => return,  // idle: the test has finished
            Err(e) => {
                eprintln!("mock UDP server: receive failed: {e}");
                return;
            }
        };

        record(log, &buf[.. len]);
        if let Udp::After(delay, _) = mode {
            thread::sleep(*delay);
        }
        for reply in mode.replies(&buf[.. len]) {
            if let Err(e) = socket.send_to(&reply, peer) {
                eprintln!("mock UDP server: send failed: {e}");
            }
        }
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
}


// ---- DNS over TCP ----

/// What a TCP server does with each connection.
#[derive(Debug, Clone)]
pub enum Tcp {

    /// Reply with this response, carrying the query’s transaction ID.
    Replay(Vec<u8>),

    /// The correct reply, written one byte at a time.
    Drip(Vec<u8>),

    /// The correct reply, one byte at a time with this long between them,
    /// as a server trying to hold the client for as long as it can sends it.
    Trickle(Vec<u8>, Duration),

    /// A reply with the wrong transaction ID.
    WrongTxid(Vec<u8>),

    /// Only the two-byte length prefix of this reply, then close.
    PrefixOnlyThenClose(Vec<u8>),

    /// The length prefix and half of this reply, then close.
    HalfBodyThenClose(Vec<u8>),

    /// A single byte, then close.
    OneByteThenClose,

    /// A zero length prefix, then close.
    ZeroLength,

    /// The correct reply followed by bytes beyond its stated length.
    TrailingBytes(Vec<u8>),

    /// Close the connection as soon as it is accepted, without reading.
    CloseImmediately,

    /// Exactly these bytes, after reading the query.
    Raw(Vec<u8>),

    /// Read the query and never reply.
    Silent,
}

/// What to do on a stream after reading the request.
pub(crate) enum Action {
    Write(Vec<u8>),
    Trickle(Vec<u8>, Duration),
    Hold,
}

/// The pause between bytes for the drip modes: long enough that each byte
/// arrives in a read of its own, short enough to keep tests quick.
const DRIP: Duration = Duration::from_millis(1);

impl Tcp {
    fn action(&self, query: &[u8]) -> Action {
        let id = request_txid(query);
        match self {
            Self::Replay(reply)               => Action::Write(prefixed(&wire::with_txid(reply, id))),
            Self::Drip(reply)                 => Action::Trickle(prefixed(&wire::with_txid(reply, id)), DRIP),
            Self::Trickle(reply, delay)       => Action::Trickle(prefixed(&wire::with_txid(reply, id)), *delay),
            Self::WrongTxid(reply)            => Action::Write(prefixed(&wire::with_txid(reply, id.wrapping_add(1)))),
            Self::PrefixOnlyThenClose(reply)  => Action::Write(prefixed(reply)[.. 2].to_vec()),
            Self::HalfBodyThenClose(reply)    => Action::Write(half_body(&prefixed(&wire::with_txid(reply, id)))),
            Self::OneByteThenClose            => Action::Write(vec![ 0 ]),
            Self::ZeroLength                  => Action::Write(vec![ 0, 0 ]),
            Self::TrailingBytes(reply)        => Action::Write([ prefixed(&wire::with_txid(reply, id)), b"trailing".to_vec() ].concat()),
            Self::Raw(bytes)                  => Action::Write(bytes.clone()),
            Self::CloseImmediately | Self::Silent => Action::Hold,
        }
    }
}

/// The message with its two-byte big-endian length prefix, as sent over TCP.
///
/// # Panics
///
/// Panics if the message is longer than 65535 bytes.
pub fn prefixed(message: &[u8]) -> Vec<u8> {
    let len = u16::try_from(message.len()).expect("the message fits a TCP length prefix");
    [ len.to_be_bytes().to_vec(), message.to_vec() ].concat()
}

fn half_body(prefixed: &[u8]) -> Vec<u8> {
    prefixed[.. 2 + (prefixed.len() - 2) / 2].to_vec()
}

/// Starts a TCP server on an ephemeral loopback port.
///
/// # Panics
///
/// Panics if the listener cannot be bound.
pub fn tcp(mode: Tcp) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback TCP listener");
    serve_tcp(listener, mode)
}

fn serve_tcp(listener: TcpListener, mode: Tcp) -> Server {
    spawn_tcp(listener, move |stream, log| handle_tcp(stream, &mode, log))
}

fn handle_tcp(mut stream: TcpStream, mode: &Tcp, log: &Log) {
    if matches!(mode, Tcp::CloseImmediately) {
        return;  // dropping the stream closes it
    }

    prepare(&stream);
    serve_dns_stream(&mut stream, mode, log);
}

/// Serves one length-prefixed DNS exchange on a stream, plain or TLS.
pub(crate) fn serve_dns_stream<S: Read + Write>(stream: &mut S, mode: &Tcp, log: &Log) {
    let query = match read_prefixed(stream) {
        Ok(query) => query,
        Err(e) => {
            eprintln!("mock TCP server: could not read the query: {e}");
            return;
        }
    };

    record(log, &query);
    if let Err(e) = perform(stream, mode.action(&query)) {
        eprintln!("mock TCP server: could not reply: {e}");
    }
}

fn read_prefixed<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut len = [0; 2];
    stream.read_exact(&mut len)?;
    let mut query = vec![0; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut query)?;
    Ok(query)
}

/// Runs a server thread that passes each accepted connection to `handler`.
pub(crate) fn spawn_tcp<F>(listener: TcpListener, handler: F) -> Server
where F: Fn(TcpStream, &Log) + Send + 'static
{
    let addr = listener.local_addr().expect("the TCP listener has a local address");
    let log = Log::default();
    let thread_log = Arc::clone(&log);
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(stream) => handler(stream, &thread_log),
                Err(e) => {
                    eprintln!("mock server: accept failed: {e}");
                    return;
                }
            }
        }
    });
    Server { addr, log }
}

/// Sets the timeouts and options every accepted connection uses.
pub(crate) fn prepare(stream: &TcpStream) {
    let results = [
        stream.set_read_timeout(Some(IDLE)),
        stream.set_write_timeout(Some(IDLE)),
        stream.set_nodelay(true),
    ];
    for result in results {
        if let Err(e) = result {
            eprintln!("mock server: could not configure the connection: {e}");
        }
    }
}

pub(crate) fn perform<S: Read + Write>(stream: &mut S, action: Action) -> io::Result<()> {
    match action {
        Action::Write(bytes)           => stream.write_all(&bytes).and_then(|()| stream.flush()),
        Action::Trickle(bytes, delay)  => trickle(stream, &bytes, delay),
        Action::Hold                   => hold(stream),
    }
}

/// Writes the bytes one at a time, pausing after each. The client giving up
/// and closing the connection partway through is what a trickling server
/// expects to happen sooner or later, so it ends the reply without error.
fn trickle<S: Write>(stream: &mut S, bytes: &[u8], delay: Duration) -> io::Result<()> {
    for byte in bytes {
        match stream.write_all(std::slice::from_ref(byte)).and_then(|()| stream.flush()) {
            Err(e) if matches!(e.kind(), io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset) => return Ok(()),
            result => result?,
        }
        thread::sleep(delay);
    }
    Ok(())
}

/// Keeps the connection open, reading and discarding, until the client
/// closes it or the idle timeout passes.
pub(crate) fn hold<S: Read>(stream: &mut S) -> io::Result<()> {
    let mut buf = [0; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) if is_timeout(&e) => return Ok(()),
            Err(e) => return Err(e),
        }
    }
}


// ---- UDP and TCP on one port ----

/// Starts a UDP server and a TCP server on the same loopback port, as a real
/// nameserver has, for the automatic transport, which retries a truncated
/// UDP answer over TCP.
///
/// # Panics
///
/// Panics if no port can be found that is free for both protocols.
pub fn udp_and_tcp(udp_mode: Udp, tcp_mode: Tcp) -> (Server, Server) {
    let (socket, listener) = port_pair();
    (serve_udp(socket, udp_mode), serve_tcp(listener, tcp_mode))
}

fn port_pair() -> (UdpSocket, TcpListener) {
    for _ in 0 .. 20 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback TCP listener");
        let port = listener.local_addr().expect("the TCP listener has a local address").port();
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(socket) => return (socket, listener),
            Err(e) => eprintln!("port {port} is taken for UDP ({e}); trying another"),
        }
    }
    panic!("could not find a loopback port free for both UDP and TCP");
}


// ---- HTTP ----

/// What an HTTP server does with each request.
#[derive(Debug, Clone)]
pub enum Http {

    /// Reply with this response. If it carries a DNS message, the request’s
    /// transaction ID is written into it.
    Reply(Vec<u8>),

    /// As `Reply`, but written one byte at a time.
    Drip(Vec<u8>),

    /// As `Reply`, but one byte at a time with this long between them.
    Trickle(Vec<u8>, Duration),

    /// Exactly these bytes, untouched.
    Raw(Vec<u8>),

    /// Read the request and never reply.
    Silent,
}

impl Http {
    fn action(&self, request: &[u8]) -> Action {
        match self {
            Self::Reply(reply)           => Action::Write(reply_for(reply, request)),
            Self::Drip(reply)            => Action::Trickle(reply_for(reply, request), DRIP),
            Self::Trickle(reply, delay)  => Action::Trickle(reply_for(reply, request), *delay),
            Self::Raw(bytes)             => Action::Write(bytes.clone()),
            Self::Silent                 => Action::Hold,
        }
    }
}

fn reply_for(reply: &[u8], request: &[u8]) -> Vec<u8> {
    let body_holds_txid = wire::http_is_dns(reply) && wire::http_body(reply).len() >= 2;
    match body_txid(request) {
        Some(id) if body_holds_txid => wire::patch_body_txid(reply, id),
        _ => reply.to_vec(),
    }
}

fn body_txid(request: &[u8]) -> Option<u16> {
    let end = wire::http_header_end(request)?;
    (request.len() >= end + 2).then(|| wire::get_u16(request, end))
}

/// Starts a plain-text HTTP server on an ephemeral loopback port.
///
/// # Panics
///
/// Panics if the listener cannot be bound.
pub fn http(mode: Http) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback TCP listener");
    spawn_tcp(listener, move |mut stream, log| {
        prepare(&stream);
        serve_http_stream(&mut stream, &mode, log);
    })
}

/// Serves one HTTP exchange on a stream, plain or TLS.
pub(crate) fn serve_http_stream<S: Read + Write>(stream: &mut S, mode: &Http, log: &Log) {
    let request = match read_http_request(stream) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("mock HTTP server: could not read the request: {e}");
            return;
        }
    };

    record(log, &request);
    if let Err(e) = perform(stream, mode.action(&request)) {
        eprintln!("mock HTTP server: could not reply: {e}");
    }
}

fn read_http_request<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0; 4096];
    loop {
        if let Some(end) = wire::http_header_end(&data) {
            if data.len() >= end + content_length(&data[.. end]) {
                return Ok(data);
            }
        }

        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the client closed before sending a whole request"));
        }
        data.extend_from_slice(&buf[.. read]);
    }
}

// ---- HTTP/2 ----

/// What an HTTP/2 server does with the request on each connection.
#[derive(Debug, Clone)]
pub enum Http2 {

    /// Reply with this response, captured from a real server, with the
    /// request’s transaction ID written into its body.
    Reply(Vec<u8>),

    /// Exactly these bytes, untouched.
    Raw(Vec<u8>),
}

impl Http2 {
    fn reply(&self, request: &[u8]) -> Vec<u8> {
        match (self, wire::h2_request_txid(request)) {
            (Self::Reply(reply), Some(id)) => wire::h2_patch_body_txid(reply, id),
            (Self::Reply(bytes) | Self::Raw(bytes), _) => bytes.clone(),
        }
    }
}

/// Starts an HTTP/2 server on an ephemeral loopback port, speaking HTTP/2
/// from the first byte, as a TLS server does once it has chosen it by ALPN.
///
/// # Panics
///
/// Panics if the listener cannot be bound.
pub fn http2(mode: Http2) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback TCP listener");
    spawn_tcp(listener, move |mut stream, log| {
        prepare(&stream);
        serve_http2_stream(&mut stream, &mode, log);
    })
}

/// Serves one HTTP/2 exchange on a stream, plain or TLS: reads the client’s
/// frames until its request is complete, and replies. The connection then
/// stays open until the client closes it, as a real server’s does, because
/// the client acknowledges the server’s settings after the reply is sent.
pub(crate) fn serve_http2_stream<S: Read + Write>(stream: &mut S, mode: &Http2, log: &Log) {
    let request = match read_h2_request(stream) {
        Ok(request) => request,
        Err(e) => {
            eprintln!("mock HTTP/2 server: could not read the request: {e}");
            return;
        }
    };

    record(log, &request);
    let reply = mode.reply(&request);
    if let Err(e) = stream.write_all(&reply).and_then(|()| stream.flush()).and_then(|()| hold(stream)) {
        eprintln!("mock HTTP/2 server: could not reply: {e}");
    }
}

/// Reads until the client has sent a frame that ends stream 1.
fn read_h2_request<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0; 4096];
    while ! wire::h2_frames(&data).iter().any(|f| f.stream == 1 && f.flags & wire::H2_END_STREAM != 0) {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the client closed before sending a whole request"));
        }
        data.extend_from_slice(&buf[.. read]);
    }
    Ok(data)
}

fn content_length(head: &[u8]) -> usize {
    String::from_utf8_lossy(head).lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse().ok())
        .unwrap_or(0)
}


#[cfg(test)]
mod test {
    use super::*;
    use std::net::TcpStream;

    const REPLY: &[u8] = &[ 0xaa, 0xaa, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0 ];
    const QUERY: &[u8] = &[ 0x12, 0x34, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0 ];

    fn udp_exchange(server: &Server, count: usize) -> Vec<Vec<u8>> {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        socket.send_to(QUERY, server.addr()).unwrap();
        let mut buf = [0; 512];
        (0 .. count).map(|_| { let (n, _) = socket.recv_from(&mut buf).unwrap(); buf[.. n].to_vec() }).collect()
    }

    fn tcp_exchange(server: &Server) -> Vec<u8> {
        let mut stream = TcpStream::connect(server.addr()).unwrap();
        stream.write_all(&prefixed(QUERY)).unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).unwrap();
        reply
    }

    #[test]
    fn udp_replay_copies_txid_and_records() {
        let server = udp(Udp::Replay(REPLY.to_vec()));
        let replies = udp_exchange(&server, 1);
        assert_eq!(wire::txid(&replies[0]), 0x1234);
        assert_eq!(server.requests(), vec![ QUERY.to_vec() ]);
        assert!(server.at().starts_with("@127.0.0.1:"));
        assert_eq!(server.port(), server.addr().port());
    }

    #[test]
    fn udp_modes() {
        let replies = udp_exchange(&udp(Udp::WrongTxidThen(REPLY.to_vec())), 2);
        assert_eq!((wire::txid(&replies[0]), wire::txid(&replies[1])), (0x1235, 0x1234));
        assert_eq!(wire::txid(&udp_exchange(&udp(Udp::OnlyWrongTxid(REPLY.to_vec())), 1)[0]), 0x1235);
        assert_eq!(wire::txid(&udp_exchange(&udp(Udp::After(Duration::from_millis(10), REPLY.to_vec())), 1)[0]), 0x1234);
        assert_eq!(wire::flags(&udp_exchange(&udp(Udp::NotAResponse(REPLY.to_vec())), 1)[0]) & wire::QR, 0);
        assert_eq!(udp_exchange(&udp(Udp::Raw(vec![ 1 ])), 1)[0], vec![ 1 ]);
        assert_eq!(udp_exchange(&udp(Udp::RawWithTxid(vec![ 0, 0, 9 ])), 1)[0], vec![ 0x12, 0x34, 9 ]);
        assert_eq!(udp_exchange(&udp(Udp::RawWithTxid(vec![ 7 ])), 1)[0], vec![ 7 ]);
    }

    #[test]
    fn tcp_modes() {
        assert_eq!(tcp_exchange(&tcp(Tcp::Replay(REPLY.to_vec()))), prefixed(&wire::with_txid(REPLY, 0x1234)));
        assert_eq!(tcp_exchange(&tcp(Tcp::Drip(REPLY.to_vec()))), prefixed(&wire::with_txid(REPLY, 0x1234)));
        assert_eq!(tcp_exchange(&tcp(Tcp::Trickle(REPLY.to_vec(), DRIP))), prefixed(&wire::with_txid(REPLY, 0x1234)));
        assert_eq!(tcp_exchange(&tcp(Tcp::PrefixOnlyThenClose(REPLY.to_vec()))), vec![ 0, 12 ]);
        assert_eq!(tcp_exchange(&tcp(Tcp::HalfBodyThenClose(REPLY.to_vec()))).len(), 2 + 6);
        assert_eq!(tcp_exchange(&tcp(Tcp::OneByteThenClose)), vec![ 0 ]);
        assert_eq!(tcp_exchange(&tcp(Tcp::ZeroLength)), vec![ 0, 0 ]);
        assert!(tcp_exchange(&tcp(Tcp::TrailingBytes(REPLY.to_vec()))).ends_with(b"trailing"));
        assert_eq!(wire::txid(&tcp_exchange(&tcp(Tcp::WrongTxid(REPLY.to_vec())))[2 ..]), 0x1235);
        assert_eq!(tcp_exchange(&tcp(Tcp::Raw(b"xyz".to_vec()))), b"xyz");
    }

    #[test]
    fn tcp_close_immediately_sends_nothing() {
        let server = tcp(Tcp::CloseImmediately);
        let mut stream = TcpStream::connect(server.addr()).unwrap();
        let mut reply = Vec::new();
        // The write may or may not fail depending on timing; the read must see the close.
        drop(stream.write_all(&prefixed(QUERY)));
        let read = stream.read_to_end(&mut reply);
        assert!(read.is_err() || reply.is_empty());
        assert!(server.requests().is_empty());
    }

    #[test]
    fn tcp_silent_holds_the_connection() {
        let server = tcp(Tcp::Silent);
        let mut stream = TcpStream::connect(server.addr()).unwrap();
        stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        stream.write_all(&prefixed(QUERY)).unwrap();
        let mut buf = [0; 16];
        let err = stream.read(&mut buf).unwrap_err();
        assert!(is_timeout(&err));
    }

    /// Echo keeps a real response’s header and records, but repeats the
    /// question it was actually sent, with that query’s transaction ID.
    #[test]
    fn udp_echo_answers_whatever_was_asked() {
        let query = crate::fixtures::query("aaaa-example");
        let reply = crate::fixtures::response("a-example");
        let server = udp(Udp::Echo(reply.clone()));

        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        socket.send_to(&query, server.addr()).unwrap();
        let mut buf = [0; 512];
        let (len, _) = socket.recv_from(&mut buf).unwrap();
        let echoed = &buf[.. len];

        assert_eq!(wire::txid(echoed), wire::txid(&query));
        assert_eq!(&echoed[wire::HEADER_LEN .. wire::question_end(echoed)], &query[wire::HEADER_LEN .. wire::question_end(&query)]);
        assert_eq!(&echoed[wire::question_end(echoed) ..], &reply[wire::question_end(&reply) ..]);
        assert_eq!(wire::counts(echoed), wire::counts(&reply));
    }

    #[test]
    fn same_port_pair() {
        let (udp_server, tcp_server) = udp_and_tcp(Udp::Replay(REPLY.to_vec()), Tcp::Replay(REPLY.to_vec()));
        assert_eq!(udp_server.port(), tcp_server.port());
        assert_eq!(udp_exchange(&udp_server, 1).len(), 1);
        assert_eq!(tcp_exchange(&tcp_server).len(), 14);
    }

    #[test]
    fn http_reply_patches_dns_bodies_only() {
        let dns_reply = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 2\r\n\r\n\x00\x00".to_vec();
        let html_reply = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno".to_vec();
        let request = [ b"POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n".as_slice(), &[ 0x12, 0x34 ] ].concat();

        for (mode, expected_body) in [
            (Http::Reply(dns_reply.clone()), b"\x12\x34".as_slice()),
            (Http::Drip(dns_reply.clone()), b"\x12\x34".as_slice()),
            (Http::Trickle(dns_reply.clone(), DRIP), b"\x12\x34".as_slice()),
            (Http::Reply(html_reply.clone()), b"no".as_slice()),
            (Http::Raw(dns_reply.clone()), b"\x00\x00".as_slice()),
        ] {
            let server = http(mode);
            let mut stream = TcpStream::connect(server.addr()).unwrap();
            stream.write_all(&request).unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).unwrap();
            assert_eq!(wire::http_body(&reply), expected_body);
            assert_eq!(server.requests(), vec![ request.clone() ]);
        }
    }

    #[test]
    fn http2_replies_carry_the_request_txid() {
        let request = [ wire::H2_PREFACE, &wire::H2Frame { kind: wire::H2_DATA, flags: wire::H2_END_STREAM, stream: 1, payload: QUERY.to_vec() }.to_bytes() ].concat();
        let reply = wire::H2Frame { kind: wire::H2_DATA, flags: wire::H2_END_STREAM, stream: 1, payload: REPLY.to_vec() }.to_bytes();

        for (mode, expected_txid) in [ (Http2::Reply(reply.clone()), 0x1234), (Http2::Raw(reply.clone()), 0xaaaa) ] {
            let server = http2(mode);
            let mut stream = TcpStream::connect(server.addr()).unwrap();
            stream.write_all(&request[.. 10]).unwrap();
            stream.write_all(&request[10 ..]).unwrap();
            let mut received = vec![ 0; reply.len() ];
            stream.read_exact(&mut received).unwrap();
            assert_eq!(wire::txid(&wire::h2_body(&received)), expected_txid);
            assert_eq!(server.requests(), vec![ request.clone() ]);
        }
    }

    #[test]
    fn http2_clients_that_close_early() {
        let server = http2(Http2::Raw(Vec::new()));
        drop(TcpStream::connect(server.addr()).unwrap());
        assert!(server.requests().is_empty());
    }

    #[test]
    fn content_length_parsing() {
        assert_eq!(content_length(b"POST / HTTP/1.1\r\ncontent-length: 12"), 12);
        assert_eq!(content_length(b"POST / HTTP/1.1\r\nContent-Length: nope"), 0);
        assert_eq!(content_length(b"POST / HTTP/1.1"), 0);
        assert_eq!(body_txid(b"POST / HTTP/1.1\r\n\r\n\x01"), None);
    }
}
