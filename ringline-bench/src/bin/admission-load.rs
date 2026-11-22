//! Load for the contended cases of Experiments B to E
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
//! - `--fast-conns` closed-loop connections each keep `--fast-depth`
//!   requests for `--fast-size` bytes outstanding: each writes that many,
//!   then one more as each reply is read in full, and reads as fast as the
//!   socket allows (Closed-loop depth connections, below).
//! - `--batch-conns` connections each run rounds of `--batch-requests`
//!   requests for `--batch-size` bytes (Batch connections, below).
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
//!   server's FIFO, then reads it as fast as it can, with `SO_RCVBUF` set to
//!   `--head-rcvbuf` before the connect (0 leaves it to the kernel). With
//!   `--large-size 0` the episode has no head.
//!
//! With `--ports-file`, each stalled peer, drainer and head appends its local
//! port to the file as it connects, so that a sampler can pick its socket out
//! of `ss`.
//!
//! # Closed loop
//!
//! With `--closed-loop N` the load runs only workload U of Experiment D: one
//! connection, with `SO_RCVBUF` set to `--head-rcvbuf` before the connect,
//! writes a request for `--large-size` bytes, reads the reply in full, and
//! writes the next, `--closed-warmup` times uncounted and then N times. It
//! prints the `SO_RCVBUF` the kernel reports, each counted reply's time from
//! its request to its last byte in microseconds, their median, p99 and
//! maximum, and the window over which they ran. It exits 1 if a reply was not
//! read in full.
//!
//! The head's tag is `u32::MAX`, each drainer's `0x8000_0000` plus its index,
//! each closed-loop depth connection's `0x4000_0000` plus its index, each
//! batch connection's `0x6000_0000` plus its index, and each stalled peer's
//! its index; `admission-server` records the tag of every large reply. Their
//! requests' scheduled times are when they are written, except a batch
//! round's, whose requests all carry the round's start.
//!
//! # Closed-loop depth connections
//!
//! Each `--fast-conns` connection starts with the warmup and stops writing
//! and reading when the window ends; replies still outstanding then are not
//! read. Its socket is blocking, with a 10 ms read timeout so that it sees
//! the window end. Its requests carry flag bit 2 when written inside the
//! window. A reply counts when its last byte is read inside the window, and
//! its latency is from its request's write to that read. A connection that
//! ends is reopened, its outstanding requests forgotten, and counted in
//! `reconnects`.
//!
//! # Batch connections
//!
//! Each `--batch-conns` connection sets `SO_RCVBUF` to `--batch-rcvbuf` and
//! `SO_SNDBUF` to `--batch-sndbuf` before the connect (0 leaves either to the
//! kernel), and its socket is non-blocking. From the start of the warmup it
//! runs rounds. A round writes all `--batch-requests` requests, waiting for
//! room in the socket while it takes none and reading nothing, then reads
//! all the replies. Its requests carry the round's start as their scheduled
//! time, and flag bit 2 if that is inside the window. A round not finished
//! `--batch-round-limit-ms` after it began is stalled: the connection closes
//! and runs no more rounds. The stall records whether the round was writing
//! or reading, the requests the socket (or under TLS, rustls) had taken, and
//! the replies read in full. A round under way when the window ends stops
//! there and is reported as unfinished, with the same fields. A connection
//! that ends otherwise is reopened, and a new round begins.
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
//! head: its time from request to last byte in milliseconds (`large_ms`) and
//! microseconds (`large_us`), `null` where it was not read in full, and
//! whether it was (`large_completed`); the same for the slow connections
//! under `slow`; each drainer's time from request to last byte per episode,
//! in milliseconds and microseconds, or `null`, and whether its reply was
//! read in full, under `drainers`; counts for the outside connections under
//! `outside`; and the window's start and end in nanoseconds of
//! `CLOCK_MONOTONIC` under `window_ns`. The closed loop prints its own
//! object (above).
//!
//! `slow.bytes_read` counts the slow connections' reply bytes over the whole
//! run, and `slow.bytes_read_window` those read inside the window.
//!
//! Under `fast`, for the closed-loop depth connections: their flags, and
//! over the window the replies read in full (`replies`), the reply bytes
//! read (`bytes_read`), both per second of `--duration` (`replies_per_s`,
//! `bytes_per_s`), the median, p99 and maximum latency in microseconds
//! (`p50_us`, `p99_us`, `max_us`, 0 with no replies), and `reconnects`.
//!
//! Under `batch`, for the batch connections: their flags; the rounds that
//! finished inside the window (`rounds`) and at any time (`rounds_run`); the
//! connections whose round stalled (`stalled`), and for each such round
//! (`stalls`) its connection's index (`conn`), the phase it stalled in
//! (`phase`, `write` or `read`), the requests written (`written`), the
//! replies read (`read`) and the time of the stall in nanoseconds of
//! `CLOCK_MONOTONIC` (`at_ns`); the rounds under way when the window ended,
//! with the same fields (`unfinished`); and `reconnects`. A stall counts
//! whenever it happens, in the warmup too.

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
    about = "The contended-case load of Experiments B to E"
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
    /// `SO_RCVBUF` on the head's socket, and on the closed loop's, set
    /// before the connect; 0 leaves it to the kernel.
    #[arg(long, default_value_t = 0)]
    head_rcvbuf: i32,
    /// Run only a closed loop of this many `--large-size` requests on one
    /// connection, each written once the reply before it has been read in
    /// full, and nothing else (Experiment D's workload U).
    #[arg(long, default_value_t = 0)]
    closed_loop: u32,
    /// Replies the closed loop reads before the ones it counts, outside the
    /// measurement window.
    #[arg(long, default_value_t = 10)]
    closed_warmup: u32,
    /// Append a line for each stalled peer, drainer and head connection to
    /// this file as it connects: the `CLOCK_MONOTONIC` time in ns, the
    /// episode, the kind (`stall`, `drain` or `head`), its index, and its
    /// local port.
    #[arg(long)]
    ports_file: Option<std::path::PathBuf>,
    /// Closed-loop connections that each keep `--fast-depth` requests
    /// outstanding.
    #[arg(long, default_value_t = 0)]
    fast_conns: usize,
    #[arg(long, default_value_t = 1024)]
    fast_size: u32,
    /// Requests each `--fast-conns` connection keeps outstanding.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    fast_depth: u32,
    /// Connections that each write `--batch-requests` requests, then read
    /// their replies, in rounds.
    #[arg(long, default_value_t = 0)]
    batch_conns: usize,
    /// Requests in one round of a batch connection.
    #[arg(long, default_value_t = 0)]
    batch_requests: u32,
    #[arg(long, default_value_t = 1024)]
    batch_size: u32,
    /// `SO_RCVBUF` on the batch connections' sockets, set before the
    /// connect; 0 leaves it to the kernel.
    #[arg(long, default_value_t = 0)]
    batch_rcvbuf: i32,
    /// `SO_SNDBUF` on the batch connections' sockets, set before the
    /// connect; 0 leaves it to the kernel.
    #[arg(long, default_value_t = 0)]
    batch_sndbuf: i32,
    /// A batch round not finished this long after it began is stalled, and
    /// its connection stops.
    #[arg(long, default_value_t = 10_000)]
    batch_round_limit_ms: u64,
}

const REQUEST_LEN: usize = 24;
const FLAG_SLOW: u32 = 1;
const FLAG_OUTSIDE: u32 = 1 << 1;
const FLAG_WINDOW: u32 = 1 << 2;
const HEAD_TAG: u32 = u32::MAX;
const DRAIN_TAG: u32 = 0x8000_0000;
const FAST_TAG: u32 = 0x4000_0000;
const BATCH_TAG: u32 = 0x6000_0000;
/// The longest a closed-loop depth or batch connection waits for its socket
/// before it checks the time again.
const SOCKET_POLL: Duration = Duration::from_millis(10);
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
    connect_wire_bufs(addr, rcvbuf, 0)
}

/// `connect_wire`, with `SO_SNDBUF` too set to `sndbuf` before the connect
/// if above 0.
fn connect_wire_bufs(addr: SocketAddr, rcvbuf: i32, sndbuf: i32) -> Wire {
    let mut failures = 0;
    loop {
        let sock = if rcvbuf > 0 || sndbuf > 0 {
            try_connect_with_bufs(addr, rcvbuf, sndbuf)
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

/// The `SO_RCVBUF` the kernel reports for `s`: on Linux twice the size set,
/// capped at `net.core.rmem_max` doubled.
fn rcvbuf(s: &TcpStream) -> i32 {
    let mut size: i32 = 0;
    let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: `s` is a live socket, and `size` and `len` outlive the call.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut size as *mut i32).cast(),
            &mut len,
        )
    };
    if rc == 0 { size } else { -1 }
}

/// Where the stalled peers', drainers' and heads' local ports are written
/// (`--ports-file`).
#[derive(Clone)]
struct Ports(Option<Arc<Mutex<std::fs::File>>>);

impl Ports {
    fn open(path: Option<&std::path::Path>) -> Ports {
        Ports(path.map(|p| {
            Arc::new(Mutex::new(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)
                    .expect("open --ports-file"),
            ))
        }))
    }

    fn note(&self, episode: usize, kind: &str, index: usize, s: &TcpStream) {
        let (Some(f), Ok(local)) = (&self.0, s.local_addr()) else {
            return;
        };
        let line = format!("{} {episode} {kind} {index} {}\n", mono_ns(), local.port());
        let _ = f.lock().unwrap().write_all(line.as_bytes());
    }
}

fn set_rcvbuf(s: &TcpStream, size: i32) {
    set_buf(s, libc::SO_RCVBUF, size);
}

/// Set the socket buffer `option` (`SO_RCVBUF` or `SO_SNDBUF`) on `s`.
fn set_buf(s: &TcpStream, option: libc::c_int, size: i32) {
    let fd = s.as_raw_fd();
    // SAFETY: `fd` is a live socket owned by `s`, and `size` outlives the call.
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
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

/// Open a socket, set `SO_RCVBUF` to `rcvbuf` and `SO_SNDBUF` to `sndbuf`
/// where each is above 0, and connect it to `addr`.
fn try_connect_with_bufs(addr: SocketAddr, rcvbuf: i32, sndbuf: i32) -> std::io::Result<TcpStream> {
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
    if rcvbuf > 0 {
        set_rcvbuf(&stream, rcvbuf);
    }
    if sndbuf > 0 {
        set_buf(&stream, libc::SO_SNDBUF, sndbuf);
    }
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
    /// Reply bytes read inside the window. Slow connections only.
    bytes_read_window: u64,
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
                    if window.contains(at) {
                        out.bytes_read_window += n as u64;
                    }
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

/// One closed-loop depth connection's results, over replies whose last byte
/// was read inside the window.
#[derive(Default)]
struct DepthConn {
    replies: u64,
    /// Reply bytes read inside the window, of any reply.
    bytes_read: u64,
    /// Each reply's time from its request's write to its last byte, in
    /// microseconds.
    latencies_us: Vec<u64>,
    reconnects: u64,
}

/// Count the replies of `size` bytes that `n` bytes just read, read at `at`,
/// complete. `left` is what the oldest unfinished reply still lacks, and
/// `written` holds each outstanding request's write time, oldest first.
/// Returns the write times of the replies completed.
fn complete_replies(
    n: usize,
    size: usize,
    left: &mut usize,
    written: &mut VecDeque<Instant>,
) -> Vec<Instant> {
    let mut done = Vec::new();
    let mut n = n;
    while n > 0 {
        let take = n.min(*left);
        n -= take;
        *left -= take;
        if *left == 0 {
            done.push(written.pop_front().expect("a reply with no request"));
            *left = size;
        }
    }
    done
}

/// One `--fast-conns` connection: from the start of the warmup until the
/// window ends, keep `--fast-depth` requests for `--fast-size` bytes
/// outstanding, writing one more as each reply is read in full, and read as
/// fast as the socket allows. A connection that ends is reopened, and the
/// requests outstanding on it are forgotten.
fn depth_conn(
    args: &Args,
    index: usize,
    start: Instant,
    window: Window,
    clock: Clock,
) -> DepthConn {
    thread::sleep(start.saturating_duration_since(Instant::now()));
    let size = args.fast_size.max(8) as usize;
    let tag = FAST_TAG | index as u32;
    let mut out = DepthConn::default();
    let mut buf = vec![0u8; 64 << 10];
    'conn: while Instant::now() < window.stop {
        let mut conn = connect(args.addr);
        conn.sock().set_read_timeout(Some(SOCKET_POLL)).ok();
        let mut written: VecDeque<Instant> = VecDeque::new();
        let mut left = size;
        while Instant::now() < window.stop {
            while written.len() < args.fast_depth as usize {
                let at = Instant::now();
                let r = request(args.fast_size, tag, window.flag(at), clock.ns(at));
                if conn.write_all(&r).is_err() {
                    out.reconnects += 1;
                    continue 'conn;
                }
                written.push_back(at);
            }
            match conn.read(&mut buf, usize::MAX) {
                Ok((0, 0)) => {}
                Ok((_, n)) => {
                    let at = Instant::now();
                    let done = complete_replies(n, size, &mut left, &mut written);
                    if window.contains(at) {
                        out.bytes_read += n as u64;
                        out.replies += done.len() as u64;
                        out.latencies_us
                            .extend(done.iter().map(|w| (at - *w).as_micros() as u64));
                    }
                    continue;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue;
                }
                Err(_) => {}
            }
            out.reconnects += 1;
            continue 'conn;
        }
    }
    out
}

/// Where a batch round stopped: the phase, the requests written and the
/// replies read by then, and when, in nanoseconds of `CLOCK_MONOTONIC`.
struct RoundStop {
    conn: usize,
    phase: &'static str,
    written: u64,
    read: u64,
    at_ns: u64,
}

impl RoundStop {
    fn json(&self) -> Value {
        json!({
            "conn": self.conn,
            "phase": self.phase,
            "written": self.written,
            "read": self.read,
            "at_ns": self.at_ns,
        })
    }
}

/// One batch connection's results.
#[derive(Default)]
struct BatchConn {
    /// Rounds that finished inside the window.
    rounds: u64,
    /// Rounds that finished, at any time.
    rounds_run: u64,
    /// The round that passed `--batch-round-limit-ms`, if one did.
    stall: Option<RoundStop>,
    /// The round under way when the window ended, if it had not stalled.
    unfinished: Option<RoundStop>,
    reconnects: u64,
}

/// How a phase of a batch round ended.
enum Phase {
    Done,
    /// The connection ended or failed.
    Broken,
    /// The round passed its limit.
    Stalled,
    /// The window ended.
    Ended,
}

/// One `--batch-conns` connection: from the start of the warmup until the
/// window ends, rounds of `--batch-requests` requests for `--batch-size`
/// bytes. A round writes every request, waiting for room in the socket as
/// needed and reading nothing, then reads every reply. A round not finished
/// `--batch-round-limit-ms` after it began is stalled: the connection closes
/// and runs no more rounds. A connection that ends otherwise is reopened, and
/// a new round begins. The requests of a round carry its start as their
/// scheduled time, and flag bit 2 if it is inside the window.
fn batch_conn(
    args: &Args,
    index: usize,
    start: Instant,
    window: Window,
    clock: Clock,
) -> BatchConn {
    thread::sleep(start.saturating_duration_since(Instant::now()));
    let size = args.batch_size.max(8) as usize;
    let k = args.batch_requests as usize;
    let tag = BATCH_TAG | index as u32;
    let limit = Duration::from_millis(args.batch_round_limit_ms);
    let mut out = BatchConn::default();
    let mut buf = vec![0u8; 64 << 10];
    let connect_batch = || {
        let w = connect_wire_bufs(args.addr, args.batch_rcvbuf, args.batch_sndbuf);
        w.sock().set_nonblocking(true).expect("non-blocking socket");
        w
    };
    let mut conn = connect_batch();
    loop {
        let began = Instant::now();
        if began >= window.stop {
            break;
        }
        let deadline = began + limit;
        // How a wait ends, or how long it may take.
        let wait_for = |now: Instant| -> Result<Duration, Phase> {
            if now >= deadline {
                Err(Phase::Stalled)
            } else if now >= window.stop {
                Err(Phase::Ended)
            } else {
                Ok(deadline
                    .min(window.stop)
                    .duration_since(now)
                    .min(SOCKET_POLL))
            }
        };
        let r = request(args.batch_size, tag, window.flag(began), clock.ns(began));
        let unsent: Vec<u8> = (0..k).flat_map(|_| r).collect();
        let mut off = 0usize;
        let mut replies = 0usize;
        let mut phase = "write";
        let written_all = loop {
            let flushed = match conn.flush() {
                Ok(f) => f,
                Err(_) => break Phase::Broken,
            };
            if flushed && off == unsent.len() {
                break Phase::Done;
            }
            if flushed {
                match conn.write(&unsent[off..]) {
                    Ok(0) => break Phase::Broken,
                    Ok(n) => {
                        off += n;
                        continue;
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                    Err(_) => break Phase::Broken,
                }
            }
            match wait_for(Instant::now()) {
                Ok(d) => {
                    wait_writable(conn.sock(), d);
                }
                Err(p) => break p,
            }
        };
        let ended = match written_all {
            Phase::Done => {
                phase = "read";
                let mut written: VecDeque<Instant> = std::iter::repeat_n(began, k).collect();
                let mut left = size;
                loop {
                    if replies == k {
                        break Phase::Done;
                    }
                    match conn.read(&mut buf, usize::MAX) {
                        Ok((0, 0)) => break Phase::Broken,
                        Ok((_, n)) => {
                            replies += complete_replies(n, size, &mut left, &mut written).len();
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            match wait_for(Instant::now()) {
                                Ok(d) => {
                                    if !conn.buffered() {
                                        wait_readable(conn.sock(), d);
                                    }
                                }
                                Err(p) => break p,
                            }
                        }
                        Err(_) => break Phase::Broken,
                    }
                }
            }
            other => other,
        };
        let stop = || RoundStop {
            conn: index,
            phase,
            written: (off / REQUEST_LEN) as u64,
            read: replies as u64,
            at_ns: mono_ns(),
        };
        match ended {
            Phase::Done => {
                out.rounds_run += 1;
                if window.contains(Instant::now()) {
                    out.rounds += 1;
                }
            }
            Phase::Broken => {
                out.reconnects += 1;
                conn = connect_batch();
            }
            Phase::Stalled => {
                out.stall = Some(stop());
                break;
            }
            Phase::Ended => {
                out.unfinished = Some(stop());
                break;
            }
        }
    }
    drop(conn);
    out
}

/// One drainer: ask for a `--drain-size` reply and read it at most at
/// `--drain-read-bps`. Returns the time from the request to the last byte, or
/// `None` if the connection ended or `until` came first.
fn drainer(
    args: &Args,
    index: usize,
    until: Instant,
    clock: Clock,
    ports: &Ports,
    episode: usize,
) -> Option<Duration> {
    let mut s = connect_with_rcvbuf(args.addr, args.drain_rcvbuf);
    ports.note(episode, "drain", index, s.sock());
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
/// byte, and each drainer's, or `None` where the connection ended first or
/// the reply was not read in full. `large` is `None` too in an episode with
/// no head (`--large-size 0`).
struct Episode {
    large: Option<Duration>,
    drainers: Vec<Option<Duration>>,
}

/// One episode's drainers, stalled peers and large reply. The stalled peers
/// stay open until 100 ms before the episode ends, so the server, not this
/// client, ends them; the drainers stop reading then. With `--large-size 0`
/// the episode has no head.
fn episode(args: &Args, at: Instant, clock: Clock, ports: &Ports, number: usize) -> Episode {
    thread::sleep(at.saturating_duration_since(Instant::now()));
    let hold_until = at + Duration::from_millis(args.episode_ms.saturating_sub(100));
    thread::scope(|scope| {
        let drainers: Vec<_> = (0..args.drainers)
            .map(|i| scope.spawn(move || drainer(args, i, hold_until, clock, ports, number)))
            .collect();
        let mut stalled = Vec::new();
        for i in 0..args.stall_peers {
            let mut s = connect(args.addr);
            set_rcvbuf(s.sock(), args.stall_rcvbuf);
            ports.note(number, "stall", i, s.sock());
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
        let took = (args.large_size > 0)
            .then(|| {
                let mut large = connect_with_rcvbuf(args.addr, args.head_rcvbuf);
                ports.note(number, "head", 0, large.sock());
                large
                    .sock()
                    .set_read_timeout(Some(Duration::from_millis(args.episode_ms)))
                    .ok();
                let began = Instant::now();
                let r = request(args.large_size, HEAD_TAG, FLAG_WINDOW, clock.ns(began));
                large.write_all(&r).ok()?;
                read_reply(&mut large, args.large_size as usize)?;
                Some(began.elapsed())
            })
            .flatten();
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

/// Read one reply of `len` bytes from `s`. `None` if the connection ended,
/// failed or timed out first.
fn read_reply(s: &mut Wire, len: usize) -> Option<()> {
    let mut left = len.max(8);
    let mut buf = vec![0u8; 1 << 20];
    while left > 0 {
        match s.read(&mut buf[..left.min(1 << 20)], usize::MAX) {
            Ok((0, 0)) | Err(_) => return None,
            Ok((_, n)) => left = left.saturating_sub(n),
        }
    }
    Some(())
}

/// Experiment D's workload U: `--closed-loop` requests for `--large-size`
/// bytes on one connection, each written once the reply before it has been
/// read in full, after `--closed-warmup` replies that are not counted. The
/// socket's `SO_RCVBUF` is `--head-rcvbuf`, set before the connect, and the
/// size the kernel reports is printed. Only the counted requests carry flag
/// bit 2, so the server records only them.
fn closed_loop(args: &Args, clock: Clock) -> Value {
    let mut s = connect_with_rcvbuf(args.addr, args.head_rcvbuf);
    let reported = rcvbuf(s.sock());
    s.sock()
        .set_read_timeout(Some(Duration::from_secs(10)))
        .ok();
    let mut us: Vec<u64> = Vec::with_capacity(args.closed_loop as usize);
    let mut error = None;
    let mut window = (0u64, 0u64);
    let total = args.closed_warmup + args.closed_loop;
    for i in 0..total {
        let counted = i >= args.closed_warmup;
        let began = Instant::now();
        if i == args.closed_warmup {
            window.0 = clock.ns(began);
        }
        let flags = if counted { FLAG_WINDOW } else { 0 };
        let r = request(args.large_size, HEAD_TAG, flags, clock.ns(began));
        if s.write_all(&r).is_err() {
            error = Some(format!("request {i}: write failed"));
            break;
        }
        if read_reply(&mut s, args.large_size as usize).is_none() {
            error = Some(format!("request {i}: reply not read in full"));
            break;
        }
        if counted {
            us.push(began.elapsed().as_micros() as u64);
        }
    }
    window.1 = clock.ns(Instant::now());
    let mut sorted = us.clone();
    sorted.sort_unstable();
    json!({
        "closed_loop": {
            "requests": args.closed_loop,
            "warmup": args.closed_warmup,
            "completed": us.len(),
            "size": args.large_size,
            "rcvbuf_set": args.head_rcvbuf,
            "rcvbuf_reported": reported,
            "p50_us": percentile(&sorted, 0.50),
            "p99_us": percentile(&sorted, 0.99),
            "max_us": sorted.last().copied().unwrap_or(0),
            "us": us,
            "error": error,
        },
        "window_ns": [window.0, window.1],
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
    wait_ready(conn, libc::POLLIN, timeout)
}

/// Wait until `conn` has room to write or `timeout` passes, as
/// `wait_readable` waits; true if it has.
fn wait_writable(conn: &TcpStream, timeout: Duration) -> bool {
    wait_ready(conn, libc::POLLOUT, timeout)
}

fn wait_ready(conn: &TcpStream, events: libc::c_short, timeout: Duration) -> bool {
    let mut pfd = libc::pollfd {
        fd: conn.as_raw_fd(),
        events,
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

fn micros(d: Option<Duration>) -> Option<u64> {
    d.map(|d| d.as_micros() as u64)
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
    if args.batch_conns > 0 && args.batch_requests == 0 {
        eprintln!("admission-load: --batch-conns needs --batch-requests");
        std::process::exit(2);
    }
    let clock = Clock::new();
    if args.closed_loop > 0 {
        let out = closed_loop(&args, clock);
        let failed = out["closed_loop"]["error"].is_string();
        println!("{out}");
        std::process::exit(i32::from(failed));
    }
    let ports = Ports::open(args.ports_file.as_deref());
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
            let mut number = 0;
            while at + Duration::from_millis(args.episode_ms) <= window.stop {
                let e = episode(&args, at, clock, &ports, number);
                episodes.lock().unwrap().push(e);
                at += Duration::from_millis(args.episode_ms);
                number += 1;
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
    let depths: Vec<_> = (0..args.fast_conns)
        .map(|i| {
            let args = args.clone();
            thread::spawn(move || depth_conn(&args, i, start, window, clock))
        })
        .collect();
    let batches: Vec<_> = (0..args.batch_conns)
        .map(|i| {
            let args = args.clone();
            thread::spawn(move || batch_conn(&args, i, start, window, clock))
        })
        .collect();
    let join = |hs: Vec<thread::JoinHandle<Conn>>| -> Vec<Conn> {
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    };
    let smalls = join(smalls);
    let outsides = join(outsides);
    let slows = join(slows);
    let depths: Vec<DepthConn> = depths.into_iter().map(|h| h.join().unwrap()).collect();
    let batches: Vec<BatchConn> = batches.into_iter().map(|h| h.join().unwrap()).collect();
    episode_thread.join().unwrap();

    let episodes = std::mem::take(&mut *episodes.lock().unwrap());
    let mut out = summary(&smalls, args.within_ms);
    out.insert("episodes".into(), json!(episodes.len()));
    out.insert(
        "large_ms".into(),
        json!(episodes.iter().map(|e| millis(e.large)).collect::<Vec<_>>()),
    );
    // Per episode's head: the time from its request to its last byte, in
    // microseconds, or null where it was not read in full.
    out.insert(
        "large_us".into(),
        json!(episodes.iter().map(|e| micros(e.large)).collect::<Vec<_>>()),
    );
    out.insert(
        "large_completed".into(),
        json!(
            episodes
                .iter()
                .map(|e| e.large.is_some())
                .collect::<Vec<_>>()
        ),
    );
    out.insert("large_size".into(), json!(args.large_size));
    out.insert("head_rcvbuf".into(), json!(args.head_rcvbuf));
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
        (
            "bytes_read_window".to_string(),
            json!(slows.iter().map(|s| s.bytes_read_window).sum::<u64>()),
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
            "us": episodes
                .iter()
                .map(|e| e.drainers.iter().map(|&d| micros(d)).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            "completed": episodes
                .iter()
                .map(|e| e.drainers.iter().map(|d| d.is_some()).collect::<Vec<_>>())
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
    let secs = args.duration as f64;
    let fast_replies: u64 = depths.iter().map(|d| d.replies).sum();
    let fast_bytes: u64 = depths.iter().map(|d| d.bytes_read).sum();
    let mut fast_us: Vec<u64> = depths
        .iter()
        .flat_map(|d| d.latencies_us.iter().copied())
        .collect();
    fast_us.sort_unstable();
    out.insert(
        "fast".into(),
        json!({
            "conns": args.fast_conns,
            "size": args.fast_size,
            "depth": args.fast_depth,
            "replies": fast_replies,
            "bytes_read": fast_bytes,
            "replies_per_s": fast_replies as f64 / secs,
            "bytes_per_s": fast_bytes as f64 / secs,
            "p50_us": percentile(&fast_us, 0.50),
            "p99_us": percentile(&fast_us, 0.99),
            "max_us": fast_us.last().copied().unwrap_or(0),
            "reconnects": depths.iter().map(|d| d.reconnects).sum::<u64>(),
        }),
    );
    out.insert(
        "batch".into(),
        json!({
            "conns": args.batch_conns,
            "requests": args.batch_requests,
            "size": args.batch_size,
            "rcvbuf": args.batch_rcvbuf,
            "sndbuf": args.batch_sndbuf,
            "round_limit_ms": args.batch_round_limit_ms,
            "rounds": batches.iter().map(|b| b.rounds).sum::<u64>(),
            "rounds_run": batches.iter().map(|b| b.rounds_run).sum::<u64>(),
            "stalled": batches.iter().filter(|b| b.stall.is_some()).count(),
            "stalls": batches
                .iter()
                .filter_map(|b| b.stall.as_ref().map(RoundStop::json))
                .collect::<Vec<_>>(),
            "unfinished": batches
                .iter()
                .filter_map(|b| b.unfinished.as_ref().map(RoundStop::json))
                .collect::<Vec<_>>(),
            "reconnects": batches.iter().map(|b| b.reconnects).sum::<u64>(),
        }),
    );
    out.insert(
        "window_ns".into(),
        json!([clock.ns(window.start), clock.ns(window.stop)]),
    );
    println!("{}", Value::Object(out));
}
