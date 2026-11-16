//! Load for the contended cases of Experiments B and C
//! (`docs/send-admission-design.md`, section 4), against `admission-server`.
//!
//! Every request is 24 bytes, in the format `admission-server` documents. It
//! carries its scheduled send time in nanoseconds of `CLOCK_MONOTONIC`: the
//! load reads that clock and `Instant` together once at start, and converts
//! each scheduled `Instant` with that offset. On Linux `Instant` reads
//! `CLOCK_MONOTONIC`, so the conversion is exact to the two reads' spacing.
//! Flag bit 2 is set on every request scheduled inside the measurement window
//! (after `--warmup`, for `--duration`), which the server's statistics count.
//! The episodes lie inside the window, so their requests always carry it.
//!
//! Throughout the run:
//! - `--small-conns` fast connections offer `--small-size` requests at
//!   `--small-rate` per second in total, open loop, evenly spaced, connection
//!   `i` offset by `i / --small-conns` of an interval, and read every reply as
//!   it arrives.
//! - `--slow-conns` slow connections each offer `--slow-size` requests at
//!   `--slow-rate` per second, spaced and offset the same way, with flag
//!   bit 0, and read at most `--slow-read-bps` (below).
//! - `--outside-conns` connections offer `--outside-size` requests at
//!   `--outside-rate` per second in total, with flag bit 1, so the server
//!   sends their replies outside the send-capacity FIFO. They read every reply
//!   as it arrives. The server drops a request whose reply the pool refuses,
//!   so a missing reply is counted as dropped, not as an error.
//!
//! Every `--episode-ms`, from the start of the window:
//! - `--drainers` connections each ask for a `--drain-size` reply and read it
//!   at most at `--drain-read-bps`, paced by the same token bucket as the slow
//!   connections, with `SO_RCVBUF` set to `--drain-rcvbuf` before the connect.
//!   Each is closed when its reply has been read, or 100 ms before the episode
//!   ends.
//! - `--stall-peers` connections each ask for a `--stall-size` reply and never
//!   read, so the replies hold send-pool slots until the server aborts them
//!   (`--settle-limit-ms` on the server). `--stall-rcvbuf` is set once the
//!   connection is established, as in Experiment B. They stay open until
//!   100 ms before the episode ends, so the server, not this client, ends
//!   them.
//! - `--large-delay-ms` later, one connection asks for a `--large-size` reply,
//!   which needs more slots than are free and waits at the head of the
//!   server's FIFO, then reads it.
//!
//! The head's tag is `u32::MAX`, each drainer's `0x8000_0000` plus its index,
//! and each stalled peer's its index; `admission-server` records the tag of
//! every large reply. Their requests' scheduled times are when they are
//! written.
//!
//! A reply's latency is measured from its request's scheduled send time to
//! the read of its last byte, so a reply delayed behind the head is charged
//! for the whole delay. A request whose connection ends before its reply
//! arrives is lost, and the connection is reopened; its schedule continues.
//!
//! # How a slow reader's replies hold send-pool slots
//!
//! A reply holds its send-pool slots from admission until the kernel has
//! taken the slots' bytes into the connection's socket send buffer, and it
//! settles when the kernel has taken its last byte. The send buffer grows to
//! at most the maximum of `net.ipv4.tcp_wmem`, since the server does not set
//! `SO_SNDBUF`. It empties only as fast as the peer's receive buffer takes
//! data, and once that buffer is full, as fast as the reader reads. The
//! receive buffer is `--slow-rcvbuf` (`SO_RCVBUF`, which Linux doubles), set
//! before the connect, as Linux requires for it to apply. At 0 the kernel
//! autotunes it within `net.ipv4.tcp_rmem`, up to several MiB by default,
//! which can take a slow reader's whole backlog and leave nothing in the send
//! pool. So once a slow reader has fallen behind by its receive
//! buffer plus the server's send buffer, each reply the server admits for it
//! waits for room in the socket and holds its slots. The same holds for a
//! drainer's reply and `--drain-rcvbuf`.
//!
//! The server reads a connection's next request only while fewer than its
//! `--pipeline` replies are unsettled, so a slow reader holds at most
//! `--pipeline` replies, `--pipeline * ceil(--slow-size / slot size)` slots.
//! It keeps that many waiting while it requests faster than it reads, that is
//! while `--slow-rate * --slow-size` exceeds `--slow-read-bps`. Its requests
//! then queue unread in the server's socket, so its latency grows through the
//! run, which is why it is reported apart from the fast connections'. With
//! `--pipeline 1` a slow reader holds at most one reply.
//!
//! A send waiting for room is woken by `POLLOUT`, which needs free space of
//! half the bytes queued (`docs/send-admission-design.md`, Alternatives
//! considered): from a full send buffer, once about a third of it has drained.
//! So a slow reader's replies settle in bursts about a third of a send buffer
//! apart. The server times each reply from when the one before it settled and
//! aborts the connection when that reaches `--settle-limit-ms`, so a reader
//! that takes longer than that to read a third of the server's send buffer is
//! aborted, and reconnects.
//!
//! A slow connection's socket is non-blocking. Its requests go to a buffer in
//! this process that is written as far as the socket takes it, so a full send
//! buffer delays requests, which keep their scheduled times, and does not stop
//! the reads. A token bucket filled at `--slow-read-bps`, holding at most
//! 4096 bytes plus 10 ms of the rate, paces the reads: each read takes at most
//! 4096 bytes and at most the tokens held, and waits until the bucket holds
//! 4096 bytes or 10 ms of the rate, whichever is less. The thread sleeps at
//! most 1 ms between checks.
//!
//! # TLS
//!
//! With `--tls`, every connection runs a rustls client session over its TCP
//! socket, trusting only the certificate in `--tls-ca` (which
//! `admission-server --tls-cert-out` writes) for the name `localhost`. The
//! handshake completes before the connection's first request; a request
//! scheduled while its connection is reconnecting keeps its scheduled time,
//! so the handshake counts in the latencies. The session reads and writes
//! the socket itself, not through `rustls::Stream`, so the socket sees the
//! same calls as without TLS:
//!
//! - `SO_RCVBUF` is set on the TCP socket as above, before the connect where
//!   it is set before the connect without TLS.
//! - A paced reader's token bucket counts the bytes read from the socket,
//!   which are ciphertext, and each read takes at most 4096 bytes of them as
//!   before. The plaintext rustls has decrypted is taken without waiting for
//!   tokens. Other reads take at most 16384 bytes of ciphertext at a time, so
//!   rustls' buffer of decrypted plaintext never overflows.
//! - The fast connections wait for the socket to be readable only when rustls
//!   holds no decrypted plaintext.
//! - A slow connection's requests are encrypted as they are written; the
//!   ciphertext the socket did not take is written before more requests are
//!   encrypted.
//!
//! The reply bytes, latencies and `bytes_read` count plaintext.
//!
//! # Output
//!
//! One JSON object: for the fast small connections, the replies offered after
//! `--warmup` (sent before the drain), delivered within `--within-ms`,
//! delivered late and lost, their latency percentiles, and each episode's
//! large-reply outcome, as in Experiment B; the same for the slow connections
//! under `slow`; each drainer's time from request to last byte per episode,
//! or `null`, under `drainers`; counts for the outside connections under
//! `outside`; and the window's start and end in nanoseconds of
//! `CLOCK_MONOTONIC` under `window_ns`.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use serde_json::{Value, json};

#[derive(Parser, Clone)]
#[command(
    name = "admission-load",
    about = "The contended-case load of Experiments B and C"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7979")]
    addr: SocketAddr,
    /// Seconds of load after the warmup.
    #[arg(long, default_value_t = 60)]
    duration: u64,
    /// Seconds before measuring.
    #[arg(long, default_value_t = 4)]
    warmup: u64,
    #[arg(long, default_value_t = 16)]
    small_conns: usize,
    /// Small requests per second, over all small connections.
    #[arg(long, default_value_t = 2000)]
    small_rate: u64,
    #[arg(long, default_value_t = 256)]
    small_size: u32,
    /// A reply counts as delivered within the limit when its latency is at
    /// most this. Experiment B sets it to the server's `--admit-limit-ms`.
    #[arg(long)]
    within_ms: u64,
    #[arg(long, default_value_t = 4000)]
    episode_ms: u64,
    #[arg(long, default_value_t = 3)]
    stall_peers: usize,
    #[arg(long, default_value_t = 2 << 20)]
    stall_size: u32,
    /// `SO_RCVBUF` on the stalled peers' sockets, so the kernel takes less of
    /// their replies and more stays in the send pool.
    #[arg(long, default_value_t = 4096)]
    stall_rcvbuf: i32,
    #[arg(long, default_value_t = 7 << 20)]
    large_size: u32,
    #[arg(long, default_value_t = 200)]
    large_delay_ms: u64,
    /// Slow small connections.
    #[arg(long, default_value_t = 0)]
    slow_conns: usize,
    /// Requests per second on each slow connection.
    #[arg(long, default_value_t = 0)]
    slow_rate: u64,
    #[arg(long, default_value_t = 4096)]
    slow_size: u32,
    /// Bytes per second each slow connection reads, at most.
    #[arg(long, default_value_t = 0)]
    slow_read_bps: u64,
    /// `SO_RCVBUF` on the slow connections' sockets, set before the connect;
    /// 0 leaves it to the kernel.
    #[arg(long, default_value_t = 4096)]
    slow_rcvbuf: i32,
    /// Drainers per episode.
    #[arg(long, default_value_t = 0)]
    drainers: usize,
    #[arg(long, default_value_t = 2 << 20)]
    drain_size: u32,
    /// Bytes per second each drainer reads, at most.
    #[arg(long, default_value_t = 0)]
    drain_read_bps: u64,
    /// `SO_RCVBUF` on the drainers' sockets, set before the connect; 0 leaves
    /// it to the kernel.
    #[arg(long, default_value_t = 4096)]
    drain_rcvbuf: i32,
    /// Connections whose replies the server sends outside the FIFO.
    #[arg(long, default_value_t = 0)]
    outside_conns: usize,
    /// Requests per second, over all outside connections.
    #[arg(long, default_value_t = 0)]
    outside_rate: u64,
    #[arg(long, default_value_t = 256)]
    outside_size: u32,
    /// Speak TLS to the server, which must run with `--tls`.
    #[arg(long, requires = "tls_ca")]
    tls: bool,
    /// The certificate (PEM) to trust for `--tls`, as `admission-server
    /// --tls-cert-out` writes it.
    #[arg(long, requires = "tls")]
    tls_ca: Option<PathBuf>,
}

const REQUEST_LEN: usize = 24;
const FLAG_SLOW: u32 = 1;
const FLAG_OUTSIDE: u32 = 1 << 1;
const FLAG_WINDOW: u32 = 1 << 2;
const HEAD_TAG: u32 = u32::MAX;
const DRAIN_TAG: u32 = 0x8000_0000;
/// The most a paced reader takes in one read.
const READ_CHUNK: usize = 4096;
/// The longest a paced reader sleeps between checks.
const PACE_SLEEP: Duration = Duration::from_millis(1);
/// The most ciphertext one TLS read takes from the socket: rustls' default
/// limit on the decrypted plaintext it holds unread.
const TLS_READ: usize = 16384;
/// Handshake attempts before the load gives up.
const HANDSHAKE_TRIES: u32 = 100;

/// The client config for `--tls`, set once in `main` before any connection.
static TLS: OnceLock<Option<Arc<rustls::ClientConfig>>> = OnceLock::new();

fn tls_config() -> Option<&'static Arc<rustls::ClientConfig>> {
    TLS.get().and_then(Option::as_ref)
}

/// A client config that trusts only the certificates in `ca`.
fn client_config(ca: &std::path::Path) -> Arc<rustls::ClientConfig> {
    use rustls_pki_types::CertificateDer;
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    let certs = CertificateDer::pem_file_iter(ca).unwrap_or_else(|e| {
        eprintln!("admission-load: read {}: {e}", ca.display());
        std::process::exit(2);
    });
    for cert in certs {
        let cert = cert.unwrap_or_else(|e| {
            eprintln!("admission-load: parse {}: {e}", ca.display());
            std::process::exit(2);
        });
        roots.add(cert).expect("a valid CA certificate");
    }
    if roots.is_empty() {
        eprintln!("admission-load: no certificate in {}", ca.display());
        std::process::exit(2);
    }
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A client TLS session and what it holds decrypted and unread.
struct Session {
    conn: rustls::ClientConnection,
    /// Decrypted plaintext not yet read.
    plain: usize,
    /// The server sent `close_notify`.
    closed: bool,
}

/// One connection to the server: a TCP socket, with a TLS session over it
/// under `--tls`. See the module docs, TLS.
struct Wire {
    sock: TcpStream,
    tls: Option<Box<Session>>,
}

impl Wire {
    /// Wrap `sock`, a blocking socket just connected, and complete the TLS
    /// handshake on it if `--tls` is set.
    fn new(mut sock: TcpStream) -> std::io::Result<Wire> {
        let Some(cfg) = tls_config() else {
            return Ok(Wire { sock, tls: None });
        };
        let name = rustls_pki_types::ServerName::try_from("localhost").expect("server name");
        let mut conn =
            rustls::ClientConnection::new(Arc::clone(cfg), name).map_err(std::io::Error::other)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut sock)?;
        }
        Ok(Wire {
            sock,
            tls: Some(Box::new(Session {
                conn,
                plain: 0,
                closed: false,
            })),
        })
    }

    fn sock(&self) -> &TcpStream {
        &self.sock
    }

    /// Whether rustls holds decrypted plaintext, or the server's
    /// `close_notify`, that a read returns without touching the socket.
    fn buffered(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| t.plain > 0 || t.closed)
    }

    /// Whether ciphertext waits to be written.
    fn wants_write(&self) -> bool {
        self.tls.as_ref().is_some_and(|t| t.conn.wants_write())
    }

    /// Write all of `data`, on a blocking socket.
    fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        let Some(t) = self.tls.as_mut() else {
            return self.sock.write_all(data);
        };
        t.conn.writer().write_all(data)?;
        while t.conn.wants_write() {
            t.conn.write_tls(&mut self.sock)?;
        }
        Ok(())
    }

    /// Write ciphertext waiting to be written, on a non-blocking socket.
    /// True if none is left.
    fn flush(&mut self) -> std::io::Result<bool> {
        let Some(t) = self.tls.as_mut() else {
            return Ok(true);
        };
        while t.conn.wants_write() {
            match t.conn.write_tls(&mut self.sock) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(_) => {}
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }

    /// Write some of `data` on a non-blocking socket, as `TcpStream::write`
    /// does. Under TLS, `WouldBlock` while earlier ciphertext waits; otherwise
    /// the plaintext rustls takes, encrypted and written as far as the
    /// socket takes it.
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if self.tls.is_none() {
            return self.sock.write(data);
        }
        if !self.flush()? {
            return Err(ErrorKind::WouldBlock.into());
        }
        let t = self.tls.as_mut().expect("a TLS session");
        let n = t.conn.writer().write(data)?;
        self.flush()?;
        Ok(n)
    }

    /// Read into `buf`, taking at most `cap` bytes from the socket. Returns
    /// the bytes taken from the socket and the reply bytes put in `buf`;
    /// `(0, 0)` is the end of the connection. Under TLS the first is
    /// ciphertext, and either can be 0 alone: a read of part of a record
    /// yields no plaintext, and plaintext rustls holds is returned without
    /// reading the socket. Errors as the socket's read, `WouldBlock` among
    /// them.
    fn read(&mut self, buf: &mut [u8], cap: usize) -> std::io::Result<(usize, usize)> {
        let Some(t) = self.tls.as_mut() else {
            let len = cap.min(buf.len());
            let n = self.sock.read(&mut buf[..len])?;
            return Ok((n, n));
        };
        if t.plain == 0 && !t.closed {
            let mut cipher = [0u8; TLS_READ];
            let n = self.sock.read(&mut cipher[..cap.min(TLS_READ)])?;
            if n == 0 {
                return Ok((0, 0));
            }
            let mut rest = &cipher[..n];
            while !rest.is_empty() {
                t.conn.read_tls(&mut rest)?;
                let state = t
                    .conn
                    .process_new_packets()
                    .map_err(std::io::Error::other)?;
                t.plain = state.plaintext_bytes_to_read();
                t.closed = state.peer_has_closed();
            }
            if t.plain == 0 && !t.closed {
                return Ok((n, 0));
            }
            let got = Self::take_plain(t, buf)?;
            return Ok((n, got));
        }
        Ok((0, Self::take_plain(t, buf)?))
    }

    /// Read decrypted plaintext into `buf`. 0 once the server has closed
    /// and nothing is left.
    fn take_plain(t: &mut Session, buf: &mut [u8]) -> std::io::Result<usize> {
        match t.conn.reader().read(buf) {
            Ok(n) => {
                t.plain -= n.min(t.plain);
                Ok(n)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(e),
        }
    }
}

/// Converts an `Instant` to nanoseconds of `CLOCK_MONOTONIC`, the clock the
/// server reads.
#[derive(Clone, Copy)]
struct Clock {
    instant: Instant,
    mono_ns: u64,
}

impl Clock {
    fn new() -> Clock {
        let instant = Instant::now();
        Clock {
            instant,
            mono_ns: mono_ns(),
        }
    }

    fn ns(&self, t: Instant) -> u64 {
        self.mono_ns + t.saturating_duration_since(self.instant).as_nanos() as u64
    }
}

fn mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid `timespec` for the call to write.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn request(len: u32, tag: u32, flags: u32, scheduled_ns: u64) -> [u8; REQUEST_LEN] {
    let mut r = [0u8; REQUEST_LEN];
    r[0..4].copy_from_slice(&len.to_le_bytes());
    r[4..8].copy_from_slice(&tag.to_le_bytes());
    r[8..12].copy_from_slice(&flags.to_le_bytes());
    r[16..24].copy_from_slice(&scheduled_ns.to_le_bytes());
    r
}

/// Connect to `addr`, retrying until it accepts, and complete the TLS
/// handshake under `--tls`. An `rcvbuf` above 0 is set as `SO_RCVBUF` before
/// the connect (`connect_with_rcvbuf`). A handshake that fails `HANDSHAKE_TRIES` times in a row ends the
/// process, since it would otherwise retry forever on a bad `--tls-ca`.
fn connect_wire(addr: SocketAddr, rcvbuf: i32) -> Wire {
    let mut failures = 0;
    loop {
        let sock = if rcvbuf > 0 {
            try_connect_with_rcvbuf(addr, rcvbuf)
        } else {
            TcpStream::connect(addr)
        };
        let Ok(sock) = sock else {
            thread::sleep(Duration::from_millis(5));
            continue;
        };
        sock.set_nodelay(true).ok();
        match Wire::new(sock) {
            Ok(w) => return w,
            Err(e) => {
                failures += 1;
                if failures >= HANDSHAKE_TRIES {
                    eprintln!("admission-load: TLS handshake failed {failures} times: {e}");
                    std::process::exit(1);
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

fn connect(addr: SocketAddr) -> Wire {
    connect_wire(addr, 0)
}

fn set_rcvbuf(s: &TcpStream, size: i32) {
    let fd = s.as_raw_fd();
    // SAFETY: `fd` is a live socket owned by `s`, and `size` outlives the call.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&size as *const i32).cast(),
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
    }
}

/// Connect as `connect` does, with `SO_RCVBUF` set to `rcvbuf` before the
/// connect, which Linux requires for the size to apply to the connection
/// (tcp(7)). 0 leaves the buffer to the kernel. macOS raises a loopback
/// connection's receive buffer to a few hundred KiB within about 50 ms of the
/// connect, whether the size was set before or just after it, so on macOS
/// this does not limit the buffer.
fn connect_with_rcvbuf(addr: SocketAddr, rcvbuf: i32) -> Wire {
    connect_wire(addr, rcvbuf)
}

fn try_connect_with_rcvbuf(addr: SocketAddr, rcvbuf: i32) -> std::io::Result<TcpStream> {
    use std::os::fd::FromRawFd;
    let family = if addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: socket(2) takes no pointers.
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a socket this function just opened and nothing else
    // owns; the stream closes it, on the error paths below too.
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    set_rcvbuf(&stream, rcvbuf);
    // SAFETY: all-zero bytes are a valid `sockaddr_storage`.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        SocketAddr::V4(a) => {
            // SAFETY: `sockaddr_storage` is large and aligned enough for any
            // socket address.
            let sin = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>()
            };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = a.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(a.ip().octets());
            std::mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(a) => {
            // SAFETY: as for the IPv4 case.
            let sin6 = unsafe {
                &mut *(&mut storage as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>()
            };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = a.port().to_be();
            sin6.sin6_flowinfo = a.flowinfo();
            sin6.sin6_addr.s6_addr = a.ip().octets();
            sin6.sin6_scope_id = a.scope_id();
            std::mem::size_of::<libc::sockaddr_in6>()
        }
    };
    // SAFETY: `storage` holds a socket address of `len` bytes and outlives
    // the call.
    let rc = unsafe {
        libc::connect(
            fd,
            (&storage as *const libc::sockaddr_storage).cast(),
            len as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stream)
}

/// A token bucket for a reader limited to `bps` bytes per second.
struct Pacer {
    bps: f64,
    tokens: f64,
    cap: f64,
    /// The tokens a read waits for: 4096 bytes or 10 ms of the rate,
    /// whichever is less.
    min_read: f64,
    last: Instant,
}

impl Pacer {
    fn new(bps: u64) -> Pacer {
        let bps = bps as f64;
        Pacer {
            bps,
            tokens: 0.0,
            cap: READ_CHUNK as f64 + bps / 100.0,
            min_read: (bps / 100.0).clamp(1.0, READ_CHUNK as f64),
            last: Instant::now(),
        }
    }

    /// The bytes the next read may take, or 0 if it should wait.
    fn allowance(&mut self, now: Instant) -> usize {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.bps).min(self.cap);
        self.last = now;
        if self.tokens < self.min_read {
            0
        } else {
            (self.tokens as usize).min(READ_CHUNK)
        }
    }

    fn take(&mut self, n: usize) {
        self.tokens -= n as f64;
    }

    /// How long until the bucket holds enough for a read, at most
    /// `PACE_SLEEP`.
    fn wait(&self) -> Duration {
        if self.bps <= 0.0 {
            return PACE_SLEEP;
        }
        let secs = (self.min_read - self.tokens).max(0.0) / self.bps;
        Duration::from_secs_f64(secs).min(PACE_SLEEP)
    }
}

/// One class of connections that offer requests open loop.
#[derive(Clone, Copy)]
struct Stream {
    conns: usize,
    /// The spacing of one connection's requests.
    interval: Duration,
    size: u32,
    flags: u32,
}

impl Stream {
    /// `rate` requests per second over `conns` connections.
    fn total(conns: usize, rate: u64, size: u32, flags: u32) -> Stream {
        let interval = (1_000_000_000 * conns as u64)
            .checked_div(rate)
            .map_or(Duration::MAX, Duration::from_nanos);
        Stream {
            conns,
            interval,
            size,
            flags,
        }
    }

    /// The first request of connection `index`.
    fn first(&self, start: Instant, index: usize) -> Instant {
        start + self.interval * index as u32 / self.conns as u32
    }
}

/// One connection's results. `latencies` holds the delivered replies'
/// latencies in nanoseconds, for requests scheduled inside the window.
#[derive(Default)]
struct Conn {
    offered: u64,
    lost: u64,
    /// Replies that did not arrive while a later one did.
    dropped: u64,
    latencies: Vec<u64>,
    reconnects: u64,
    bytes_read: u64,
    /// For requests scheduled in the window, how late each was written, in
    /// nanoseconds after its scheduled time. Fast connections only.
    send_late: Vec<u64>,
}

/// The measurement window and the end of the drain after it.
#[derive(Clone, Copy)]
struct Window {
    start: Instant,
    stop: Instant,
    drain: Instant,
}

impl Window {
    fn contains(&self, t: Instant) -> bool {
        t >= self.start && t < self.stop
    }

    fn flag(&self, t: Instant) -> u32 {
        if self.contains(t) { FLAG_WINDOW } else { 0 }
    }
}

/// Match a reply's tag to the oldest request still waiting, and record its
/// latency. With `gaps`, requests ahead of it that have no reply are counted
/// as dropped.
fn take_reply(
    out: &mut Conn,
    pending: &mut VecDeque<(u32, Instant)>,
    got: u32,
    at: Instant,
    window: &Window,
    gaps: bool,
) {
    loop {
        let (want, scheduled) = pending.pop_front().expect("a reply with no request");
        if want == got {
            if window.contains(scheduled) {
                out.latencies.push((at - scheduled).as_nanos() as u64);
            }
            return;
        }
        assert!(gaps, "replies out of order");
        if window.contains(scheduled) {
            out.dropped += 1;
        }
    }
}

/// Offer one fast connection's share of `stream`'s requests, open loop, until
/// the window ends, then wait until the drain ends for the replies still due.
/// With `gaps`, a reply the server dropped is counted, not an error.
fn fast_conn(
    args: &Args,
    stream: Stream,
    gaps: bool,
    index: usize,
    start: Instant,
    window: Window,
    clock: Clock,
) -> Conn {
    let mut out = Conn::default();
    let mut next = stream.first(start, index);
    // The server's replies are at least 8 bytes.
    let size = (stream.size as usize).max(8);
    let mut conn = connect(args.addr);
    let mut pending: VecDeque<(u32, Instant)> = VecDeque::new();
    let mut buf = vec![0u8; size * 64];
    let mut filled = 0usize;
    let mut tag = 0u32;
    loop {
        let now = Instant::now();
        if now >= window.drain || (now >= window.stop && pending.is_empty()) {
            break;
        }
        let mut broken = false;
        while next <= now && next < window.stop {
            let flags = stream.flags | window.flag(next);
            let r = request(stream.size, tag, flags, clock.ns(next));
            if conn.write_all(&r).is_err() {
                broken = true;
                break;
            }
            if window.contains(next) {
                out.offered += 1;
                out.send_late
                    .push(Instant::now().saturating_duration_since(next).as_nanos() as u64);
            }
            pending.push_back((tag, next));
            tag = tag.wrapping_add(1);
            next += stream.interval;
        }
        if !broken {
            let wait = if next < window.stop {
                next.saturating_duration_since(Instant::now())
            } else {
                window.drain.saturating_duration_since(Instant::now())
            };
            if !conn.buffered() && !wait_readable(conn.sock(), wait) {
                continue;
            }
            match conn.read(&mut buf[filled..], usize::MAX) {
                Ok((0, 0)) => broken = true,
                Ok((_, n)) => {
                    out.bytes_read += n as u64;
                    filled += n;
                    let at = Instant::now();
                    let mut used = 0;
                    while filled - used >= size {
                        let got = u32::from_le_bytes(buf[used..used + 4].try_into().unwrap());
                        take_reply(&mut out, &mut pending, got, at, &window, gaps);
                        used += size;
                    }
                    buf.copy_within(used..filled, 0);
                    filled -= used;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => broken = true,
            }
        }
        if broken {
            out.lost += pending.iter().filter(|(_, t)| window.contains(*t)).count() as u64;
            pending.clear();
            filled = 0;
            out.reconnects += 1;
            conn = connect(args.addr);
        }
    }
    out.lost += pending.iter().filter(|(_, t)| window.contains(*t)).count() as u64;
    out
}

fn slow_connect(args: &Args) -> Wire {
    let s = connect_with_rcvbuf(args.addr, args.slow_rcvbuf);
    s.sock().set_nonblocking(true).expect("non-blocking socket");
    s
}

/// Offer one slow connection's requests, open loop, and read its replies at
/// most at `--slow-read-bps`, until the window ends; then keep reading until
/// the drain ends or every reply has arrived. See the module docs.
fn slow_conn(args: &Args, index: usize, start: Instant, window: Window, clock: Clock) -> Conn {
    let stream = Stream {
        conns: args.slow_conns,
        interval: Duration::from_nanos(1_000_000_000 / args.slow_rate),
        size: args.slow_size,
        flags: FLAG_SLOW,
    };
    let mut out = Conn::default();
    let mut next = stream.first(start, index);
    let size = (args.slow_size as usize).max(8);
    let mut conn = slow_connect(args);
    let mut pacer = Pacer::new(args.slow_read_bps);
    let mut pending: VecDeque<(u32, Instant)> = VecDeque::new();
    let mut unsent: VecDeque<u8> = VecDeque::new();
    let mut buf = vec![0u8; size + READ_CHUNK];
    let mut filled = 0usize;
    let mut tag = 0u32;
    loop {
        let now = Instant::now();
        if now >= window.drain || (now >= window.stop && pending.is_empty()) {
            break;
        }
        while next <= now && next < window.stop {
            let flags = stream.flags | window.flag(next);
            unsent.extend(request(stream.size, tag, flags, clock.ns(next)));
            if window.contains(next) {
                out.offered += 1;
            }
            pending.push_back((tag, next));
            tag = tag.wrapping_add(1);
            next += stream.interval;
        }
        // Under TLS, ciphertext the socket did not take last time goes first.
        let mut broken = conn.flush().is_err();
        while !broken && !unsent.is_empty() {
            let (head, _) = unsent.as_slices();
            match conn.write(head) {
                Ok(0) => {
                    broken = true;
                    break;
                }
                Ok(n) => drop(unsent.drain(..n)),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    broken = true;
                    break;
                }
            }
        }
        // Whether the socket had nothing to read while the bucket allowed it.
        let mut starved = false;
        while !broken {
            let allow = pacer.allowance(Instant::now()).min(buf.len() - filled);
            if allow == 0 && !conn.buffered() {
                break;
            }
            match conn.read(&mut buf[filled..], allow) {
                Ok((0, 0)) => broken = true,
                Ok((wire, n)) => {
                    pacer.take(wire);
                    out.bytes_read += n as u64;
                    filled += n;
                    let at = Instant::now();
                    let mut used = 0;
                    while filled - used >= size {
                        let got = u32::from_le_bytes(buf[used..used + 4].try_into().unwrap());
                        take_reply(&mut out, &mut pending, got, at, &window, false);
                        used += size;
                    }
                    buf.copy_within(used..filled, 0);
                    filled -= used;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    starved = true;
                    break;
                }
                Err(_) => broken = true,
            }
        }
        if broken {
            out.lost += pending.iter().filter(|(_, t)| window.contains(*t)).count() as u64;
            pending.clear();
            unsent.clear();
            filled = 0;
            out.reconnects += 1;
            conn = slow_connect(args);
            continue;
        }
        let now = Instant::now();
        let mut sleep = if starved || !unsent.is_empty() || conn.wants_write() {
            PACE_SLEEP
        } else {
            pacer.wait()
        };
        if next < window.stop {
            sleep = sleep.min(next.saturating_duration_since(now));
        }
        thread::sleep(sleep);
    }
    out.lost += pending.iter().filter(|(_, t)| window.contains(*t)).count() as u64;
    out
}

/// One drainer: ask for a `--drain-size` reply and read it at most at
/// `--drain-read-bps`. Returns the time from the request to the last byte, or
/// `None` if the connection ended or `until` came first.
fn drainer(args: &Args, index: usize, until: Instant, clock: Clock) -> Option<Duration> {
    let mut s = connect_with_rcvbuf(args.addr, args.drain_rcvbuf);
    let began = Instant::now();
    let r = request(
        args.drain_size,
        DRAIN_TAG | index as u32,
        FLAG_WINDOW,
        clock.ns(began),
    );
    s.write_all(&r).ok()?;
    let mut pacer = Pacer::new(args.drain_read_bps);
    let mut left = args.drain_size.max(8) as usize;
    let mut buf = [0u8; READ_CHUNK];
    while left > 0 {
        let now = Instant::now();
        if now >= until {
            return None;
        }
        let allow = pacer.allowance(now).min(left);
        if allow == 0 && !s.buffered() {
            thread::sleep(pacer.wait().min(until - now));
            continue;
        }
        s.sock().set_read_timeout(Some(PACE_SLEEP)).ok();
        match s.read(&mut buf[..left.min(READ_CHUNK)], allow) {
            Ok((0, 0)) => return None,
            Ok((wire, n)) => {
                pacer.take(wire);
                left = left.saturating_sub(n);
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => return None,
        }
    }
    Some(began.elapsed())
}

/// One episode's outcome: the large reply's time from request to its last
/// byte, and each drainer's, or `None` where the connection ended first.
struct Episode {
    large: Option<Duration>,
    drainers: Vec<Option<Duration>>,
}

/// One episode's drainers, stalled peers and large reply. The stalled peers
/// stay open until 100 ms before the episode ends, so the server, not this
/// client, ends them; the drainers stop reading then.
fn episode(args: &Args, at: Instant, clock: Clock) -> Episode {
    thread::sleep(at.saturating_duration_since(Instant::now()));
    let hold_until = at + Duration::from_millis(args.episode_ms.saturating_sub(100));
    thread::scope(|scope| {
        let drainers: Vec<_> = (0..args.drainers)
            .map(|i| scope.spawn(move || drainer(args, i, hold_until, clock)))
            .collect();
        let mut stalled = Vec::new();
        for i in 0..args.stall_peers {
            let mut s = connect(args.addr);
            set_rcvbuf(s.sock(), args.stall_rcvbuf);
            let r = request(
                args.stall_size,
                i as u32,
                FLAG_WINDOW,
                clock.ns(Instant::now()),
            );
            s.write_all(&r).ok();
            stalled.push(s);
        }
        thread::sleep(Duration::from_millis(args.large_delay_ms));
        let mut large = connect(args.addr);
        large
            .sock()
            .set_read_timeout(Some(Duration::from_millis(args.episode_ms)))
            .ok();
        let began = Instant::now();
        let r = request(args.large_size, HEAD_TAG, FLAG_WINDOW, clock.ns(began));
        let took = large.write_all(&r).ok().and_then(|()| {
            let mut left = args.large_size as usize;
            let mut buf = vec![0u8; 1 << 20];
            while left > 0 {
                match large.read(&mut buf, usize::MAX) {
                    Ok((0, 0)) | Err(_) => return None,
                    Ok((_, n)) => left = left.saturating_sub(n),
                }
            }
            Some(began.elapsed())
        });
        thread::sleep(hold_until.saturating_duration_since(Instant::now()));
        drop(stalled);
        Episode {
            large: took,
            drainers: drainers
                .into_iter()
                .map(|h| h.join().expect("drainer thread"))
                .collect(),
        }
    })
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[i]
}

/// Wait until `conn` has data to read or `timeout` passes; true if it has.
///
/// The fast connections wait for their next send time here. A blocking read
/// under `SO_RCVTIMEO` rounds its timeout up to the kernel's timer tick, so a
/// connection that waited that way wrote its next request up to a tick late,
/// and every delay measured from the scheduled time carried that lateness.
/// `ppoll` takes a nanosecond timeout. Where there is no `ppoll` (macOS),
/// `poll` waits whole milliseconds, rounded down, and the loop comes back
/// early rather than late.
fn wait_readable(conn: &TcpStream, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: conn.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    #[cfg(target_os = "linux")]
    let n = {
        let ts = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        // SAFETY: one valid `pollfd` and a valid `timespec` for the call; no
        // signal mask is passed.
        unsafe { libc::ppoll(&mut pfd, 1, &ts, std::ptr::null()) }
    };
    #[cfg(not(target_os = "linux"))]
    let n = {
        let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: one valid `pollfd` for the call.
        unsafe { libc::poll(&mut pfd, 1, ms) }
    };
    n > 0
}

/// The fields Experiment B reports for its small connections, over `conns`.
fn summary(conns: &[Conn], within_ms: u64) -> serde_json::Map<String, Value> {
    let offered: u64 = conns.iter().map(|s| s.offered).sum();
    let lost: u64 = conns.iter().map(|s| s.lost).sum();
    let reconnects: u64 = conns.iter().map(|s| s.reconnects).sum();
    let mut lat: Vec<u64> = conns
        .iter()
        .flat_map(|s| s.latencies.iter().copied())
        .collect();
    lat.sort_unstable();
    let mut send_late: Vec<u64> = conns
        .iter()
        .flat_map(|s| s.send_late.iter().copied())
        .collect();
    send_late.sort_unstable();
    let within_ns = within_ms * 1_000_000;
    let within = lat.iter().filter(|&&l| l <= within_ns).count() as u64;
    let late = lat.len() as u64 - within;
    let Value::Object(map) = json!({
        "offered": offered,
        "delivered_within": within,
        "delivered_late": late,
        "lost": lost,
        "not_within": offered - within,
        "reconnects": reconnects,
        "within_ms": within_ms,
        "p50_ns": percentile(&lat, 0.50),
        "p99_ns": percentile(&lat, 0.99),
        "p999_ns": percentile(&lat, 0.999),
        "max_ns": lat.last().copied().unwrap_or(0),
        "send_late_ns": {
            "p50": percentile(&send_late, 0.50),
            "p99": percentile(&send_late, 0.99),
            "max": send_late.last().copied().unwrap_or(0),
        },
    }) else {
        unreachable!("a JSON object literal")
    };
    map
}

fn millis(d: Option<Duration>) -> Option<u64> {
    d.map(|d| d.as_millis() as u64)
}

fn main() {
    let args = Args::parse();
    let _ = TLS.set(
        args.tls_ca
            .as_deref()
            .filter(|_| args.tls)
            .map(client_config),
    );
    if args.slow_conns > 0 && args.slow_rate == 0 {
        eprintln!("admission-load: --slow-conns needs --slow-rate");
        std::process::exit(2);
    }
    if args.outside_conns > 0 && args.outside_rate == 0 {
        eprintln!("admission-load: --outside-conns needs --outside-rate");
        std::process::exit(2);
    }
    let clock = Clock::new();
    let start = Instant::now() + Duration::from_millis(200);
    let window = {
        let start_at = start + Duration::from_secs(args.warmup);
        let stop = start_at + Duration::from_secs(args.duration);
        Window {
            start: start_at,
            stop,
            drain: stop + Duration::from_millis(args.within_ms) + Duration::from_secs(2),
        }
    };

    let episodes = Arc::new(Mutex::new(Vec::new()));
    let episode_thread = {
        let args = args.clone();
        let episodes = Arc::clone(&episodes);
        thread::spawn(move || {
            let mut at = window.start;
            while at + Duration::from_millis(args.episode_ms) <= window.stop {
                let e = episode(&args, at, clock);
                episodes.lock().unwrap().push(e);
                at += Duration::from_millis(args.episode_ms);
            }
        })
    };
    let small = Stream::total(args.small_conns, args.small_rate, args.small_size, 0);
    let outside = Stream::total(
        args.outside_conns,
        args.outside_rate,
        args.outside_size,
        FLAG_OUTSIDE,
    );
    let spawn_fast = |stream: Stream, gaps: bool| -> Vec<_> {
        (0..stream.conns)
            .map(|i| {
                let args = args.clone();
                thread::spawn(move || fast_conn(&args, stream, gaps, i, start, window, clock))
            })
            .collect()
    };
    let smalls = spawn_fast(small, false);
    let outsides = spawn_fast(outside, true);
    let slows: Vec<_> = (0..args.slow_conns)
        .map(|i| {
            let args = args.clone();
            thread::spawn(move || slow_conn(&args, i, start, window, clock))
        })
        .collect();
    let join = |hs: Vec<thread::JoinHandle<Conn>>| -> Vec<Conn> {
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    };
    let smalls = join(smalls);
    let outsides = join(outsides);
    let slows = join(slows);
    episode_thread.join().unwrap();

    let episodes = std::mem::take(&mut *episodes.lock().unwrap());
    let mut out = summary(&smalls, args.within_ms);
    out.insert("episodes".into(), json!(episodes.len()));
    out.insert(
        "large_ms".into(),
        json!(episodes.iter().map(|e| millis(e.large)).collect::<Vec<_>>()),
    );
    let mut slow = summary(&slows, args.within_ms);
    slow.extend([
        ("conns".to_string(), json!(args.slow_conns)),
        ("rate".to_string(), json!(args.slow_rate)),
        ("size".to_string(), json!(args.slow_size)),
        ("read_bps".to_string(), json!(args.slow_read_bps)),
        ("rcvbuf".to_string(), json!(args.slow_rcvbuf)),
        (
            "bytes_read".to_string(),
            json!(slows.iter().map(|s| s.bytes_read).sum::<u64>()),
        ),
    ]);
    out.insert("slow".into(), Value::Object(slow));
    out.insert(
        "drainers".into(),
        json!({
            "per_episode": args.drainers,
            "size": args.drain_size,
            "read_bps": args.drain_read_bps,
            "rcvbuf": args.drain_rcvbuf,
            "ms": episodes
                .iter()
                .map(|e| e.drainers.iter().map(|&d| millis(d)).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
        }),
    );
    out.insert(
        "outside".into(),
        json!({
            "conns": args.outside_conns,
            "rate": args.outside_rate,
            "size": args.outside_size,
            "offered": outsides.iter().map(|s| s.offered).sum::<u64>(),
            "delivered": outsides.iter().map(|s| s.latencies.len() as u64).sum::<u64>(),
            "dropped": outsides.iter().map(|s| s.dropped).sum::<u64>(),
            "lost": outsides.iter().map(|s| s.lost).sum::<u64>(),
            "reconnects": outsides.iter().map(|s| s.reconnects).sum::<u64>(),
        }),
    );
    out.insert(
        "window_ns".into(),
        json!([clock.ns(window.start), clock.ns(window.stop)]),
    );
    println!("{}", Value::Object(out));
}
