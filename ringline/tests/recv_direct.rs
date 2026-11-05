//! Direct receives: a plaintext connection, accepted or from `connect` or
//! `connect_unix`, receives with one-shot receives into its own accumulator.
#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// Payload byte `i` of message `m`.
fn pattern(m: usize, i: usize) -> u8 {
    (m.wrapping_mul(31).wrapping_add(i) % 251) as u8
}

/// Message sizes: small, around the 64 KiB region, and larger than it.
fn sizes() -> Vec<usize> {
    let mut v = Vec::new();
    for k in 0..400 {
        v.push(match k % 8 {
            0 => 1,
            1 => 17,
            2 => 200,
            3 => 4096,
            4 => 65_536 - 4,
            5 => 100_000,
            6 => (1 << 20) + 3,
            _ => 31,
        });
    }
    v
}

/// Serve one connection: every message is a 4-byte big-endian length and a
/// patterned payload, written in uneven pieces with pauses between some, so
/// receives end at arbitrary points in a message.
fn serve_frames(listener: TcpListener) {
    let (mut s, _) = listener.accept().unwrap();
    let mut out = Vec::new();
    for (m, &n) in sizes().iter().enumerate() {
        out.extend_from_slice(&(n as u32).to_be_bytes());
        out.extend((0..n).map(|i| pattern(m, i)));
    }
    let mut at = 0;
    let mut step = 1usize;
    while at < out.len() {
        step = (step * 7 + 13) % 300_000 + 1;
        let end = (at + step).min(out.len());
        s.write_all(&out[at..end]).unwrap();
        at = end;
        if step.is_multiple_of(5) {
            std::thread::sleep(Duration::from_micros(200));
        }
    }
}

static SERVER: Mutex<Option<SocketAddr>> = Mutex::new(None);
static RESULT: Mutex<Option<Result<usize, String>>> = Mutex::new(None);

/// Parse one frame from `b`. A complete frame's payload is checked against
/// the pattern for message `m`; `keep` holds every fourth payload slice
/// alive across the next read, so the accumulator's remainder is sometimes
/// shared and has to be copied rather than reclaimed in place.
fn parse(m: usize, b: &[u8]) -> Result<ParseResult, String> {
    if b.len() < 4 {
        return Ok(ParseResult::NeedMore);
    }
    let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
    if n != sizes()[m] {
        return Err(format!("message {m}: length {n}, expected {}", sizes()[m]));
    }
    if b.len() < 4 + n {
        return Ok(ParseResult::NeedAtLeast(4 + n - b.len()));
    }
    if let Some(i) = (0..n).find(|&i| b[4 + i] != pattern(m, i)) {
        return Err(format!("message {m} of {n} bytes differs at {i}"));
    }
    Ok(ParseResult::Consumed(4 + n))
}

async fn read_all(mut conn: Connection, use_bytes: bool) -> Result<usize, String> {
    let total = sizes().len();
    let mut keep: Vec<Bytes> = Vec::new();
    for m in 0..total {
        let mut err = None;
        let n = if use_bytes {
            conn.with_bytes(|b| match parse(m, &b) {
                Ok(ParseResult::Consumed(c)) => {
                    if m % 4 == 0 {
                        keep.push(b.slice(4..c));
                    }
                    ParseResult::Consumed(c)
                }
                Ok(r) => r,
                Err(e) => {
                    err = Some(e);
                    ParseResult::Consumed(b.len())
                }
            })
            .await
        } else {
            conn.with_data(|b| match parse(m, b) {
                Ok(r) => r,
                Err(e) => {
                    err = Some(e);
                    ParseResult::Consumed(b.len())
                }
            })
            .await
        };
        if let Some(e) = err {
            return Err(e);
        }
        if n == 0 {
            return Err(format!("EOF before message {m}"));
        }
        if keep.len() > 2 {
            keep.remove(0);
        }
    }
    Ok(total)
}

fn run_client<H: AsyncEventHandler>() -> Result<usize, String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *RESULT.lock().unwrap() = None;
    let server = std::thread::spawn(move || serve_frames(listener));
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config).launch::<H>().expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    RESULT
        .lock()
        .unwrap()
        .take()
        .expect("client did not finish")
}

struct BytesClient;

impl AsyncEventHandler for BytesClient {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = match ringline::connect(addr).await {
                Ok(conn) => read_all(conn, true).await,
                Err(e) => Err(format!("connect: {e}")),
            };
            *RESULT.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BytesClient
    }
}

struct DataClient;

impl AsyncEventHandler for DataClient {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = match ringline::connect(addr).await {
                Ok(conn) => read_all(conn, false).await,
                Err(e) => Err(format!("connect: {e}")),
            };
            *RESULT.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        DataClient
    }
}

static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn with_bytes_reads_every_byte_in_order() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(run_client::<BytesClient>(), Ok(sizes().len()));
}

#[test]
fn with_data_reads_every_byte_in_order() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(run_client::<DataClient>(), Ok(sizes().len()));
}

// ── Close with a receive in flight ──────────────────────────────────

/// The first connection parks a read (its receive is armed), drops the read
/// on a timeout and closes. The second connection, which takes the same
/// slot, must receive only its own bytes.
struct CloseWhileArmed;

static SERVER2: Mutex<Option<SocketAddr>> = Mutex::new(None);

impl AsyncEventHandler for CloseWhileArmed {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER2.lock().unwrap().unwrap();
            let r = async {
                let mut first = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect 1: {e}"))?;
                let waited = ringline::timeout(
                    Duration::from_millis(100),
                    first.with_bytes(|b| ParseResult::Consumed(b.len())),
                )
                .await;
                if waited.is_ok() {
                    return Err("the first connection received bytes".to_string());
                }
                first.close();
                drop(first);
                // Let the Close complete so the slot is free to reuse.
                ringline::sleep(Duration::from_millis(50)).await;
                let mut second = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect 2: {e}"))?;
                let mut got = Vec::new();
                while got.len() < 4 {
                    let n = second
                        .with_bytes(|b| {
                            got.extend_from_slice(&b);
                            ParseResult::Consumed(b.len())
                        })
                        .await;
                    if n == 0 {
                        break;
                    }
                }
                if got != b"two!" {
                    return Err(format!("second connection read {got:?}"));
                }
                Ok(1)
            }
            .await;
            *RESULT.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        CloseWhileArmed
    }
}

#[test]
fn a_receive_armed_at_close_does_not_reach_the_next_connection() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER2.lock().unwrap() = Some(listener.local_addr().unwrap());
    *RESULT.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        // The first connection gets bytes only after the client has closed
        // it, so they could reach only a receive still armed for it.
        let (mut a, _) = listener.accept().unwrap();
        let (mut b, _) = listener.accept().unwrap();
        let _ = a.write_all(b"one!");
        std::thread::sleep(Duration::from_millis(50));
        b.write_all(b"two!").unwrap();
        std::thread::sleep(Duration::from_millis(200));
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(1)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<CloseWhileArmed>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        RESULT
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(1)
    );
}

// ── A NeedAtLeast larger than the message ───────────────────────────

/// Frames of `OVER_SIZE` payload bytes, parsed by a reader that announces
/// `OVER_NEED` missing bytes until the frame is complete. The documented
/// contract is that an overestimate costs memory; a direct connection must
/// still wake the reader with each receive.
const OVER_SIZE: usize = 200_000;
const OVER_COUNT: usize = 5;
const OVER_NEED: usize = 10 << 20;

struct Overestimate;

impl AsyncEventHandler for Overestimate {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                for m in 0..OVER_COUNT {
                    let n = conn
                        .with_bytes(|b| {
                            if b.len() < 4 + OVER_SIZE {
                                return ParseResult::NeedAtLeast(OVER_NEED);
                            }
                            ParseResult::Consumed(4 + OVER_SIZE)
                        })
                        .await;
                    if n == 0 {
                        return Err(format!("EOF before frame {m}"));
                    }
                }
                Ok(OVER_COUNT)
            }
            .await;
            *RESULT.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        Overestimate
    }
}

#[test]
fn an_overestimated_need_does_not_stall_a_direct_read() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *RESULT.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        for _ in 0..OVER_COUNT {
            s.write_all(&(OVER_SIZE as u32).to_be_bytes()).unwrap();
            s.write_all(&vec![0x5a; OVER_SIZE]).unwrap();
        }
        // Hold the connection open: the reader must finish on the bytes
        // alone, not on EOF.
        let mut rest = [0u8; 1];
        let _ = std::io::Read::read(&mut s, &mut rest);
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Overestimate>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        RESULT
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(OVER_COUNT)
    );
}

// ── A reset in the middle of a message ──────────────────────────────

struct ResetMidMessage;

static RESET_RESULT: Mutex<Option<Result<(), String>>> = Mutex::new(None);

impl AsyncEventHandler for ResetMidMessage {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                // A 100,000-byte frame of which the peer sends 2,000 bytes,
                // in two writes, before resetting the connection.
                let r = conn
                    .with_data_result(|b| {
                        if b.len() < 4 {
                            return ParseResult::NeedMore;
                        }
                        let n = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
                        if b.len() < 4 + n {
                            return ParseResult::NeedAtLeast(4 + n - b.len());
                        }
                        ParseResult::Consumed(4 + n)
                    })
                    .await;
                match r {
                    Ok(0) => Err("the reset was reported as a clean EOF".into()),
                    Ok(n) => Err(format!("read a whole frame of {n} bytes")),
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
                    Err(e) => Err(format!("unexpected error: {e}")),
                }
            }
            .await;
            *RESET_RESULT.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        ResetMidMessage
    }
}

#[test]
fn a_reset_in_the_middle_of_a_message_is_an_error() {
    use std::os::fd::AsRawFd;
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *RESET_RESULT.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(&100_000u32.to_be_bytes()).unwrap();
        s.write_all(&[0x5a; 1000]).unwrap();
        // By now the reader has parsed the header and armed a receive for
        // the rest of the frame; it gets 1,000 more bytes before the reset.
        std::thread::sleep(Duration::from_millis(100));
        s.write_all(&[0x5a; 1000]).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // SO_LINGER with a zero timeout: close sends a RST.
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: 0,
        };
        let rc = unsafe {
            libc::setsockopt(
                s.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                (&linger as *const libc::linger).cast(),
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0, "setsockopt SO_LINGER");
        drop(s);
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<ResetMidMessage>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        RESET_RESULT
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

static READY: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Read part of a message, give up on the rest so the direct receive stays
/// armed with the part in its buffer, then wait with `recv_ready`, which
/// resolves at once because the part counts as buffered.
struct ReadyWithPart;

impl AsyncEventHandler for ReadyWithPart {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let read = ringline::timeout(
                    Duration::from_millis(300),
                    conn.with_data(|b| {
                        if b.len() < 200 {
                            ParseResult::NeedMore
                        } else {
                            ParseResult::Consumed(200)
                        }
                    }),
                )
                .await;
                if read.is_ok() {
                    return Err("the read finished without the rest of the message".into());
                }
                ringline::timeout(Duration::from_secs(2), conn.recv_ready())
                    .await
                    .map_err(|_| {
                        "recv_ready did not resolve with part of a message held".to_string()
                    })
            }
            .await;
            *READY.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        ReadyWithPart
    }
}

#[test]
fn recv_ready_counts_the_bytes_a_direct_receive_holds() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *READY.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.write_all(&[7u8; 100]).unwrap();
        // Hold the rest until the client has finished or 5 s have passed.
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = std::io::Read::read(&mut s, &mut [0u8; 1]);
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<ReadyWithPart>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        READY.lock().unwrap().take().expect("client did not finish"),
        Ok(())
    );
}

static STREAM: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Read with `ConnStream` on a direct connection: `read` and `fill_buf`
/// each arm a receive when they park.
struct StreamRead;

impl AsyncEventHandler for StreamRead {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            use futures_util::io::{AsyncBufReadExt, AsyncReadExt};
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut stream = ringline::ConnStream::new(conn);
                let mut buf = [0u8; 5];
                ringline::timeout(Duration::from_secs(2), stream.read_exact(&mut buf))
                    .await
                    .map_err(|_| "read did not resolve".to_string())?
                    .map_err(|e| format!("read: {e}"))?;
                if &buf != b"hello" {
                    return Err(format!("read {buf:?}"));
                }
                let got = ringline::timeout(Duration::from_secs(2), stream.fill_buf())
                    .await
                    .map_err(|_| "fill_buf did not resolve".to_string())?
                    .map_err(|e| format!("fill_buf: {e}"))?
                    .to_vec();
                if got != b"world" {
                    return Err(format!("fill_buf {got:?}"));
                }
                stream.consume_unpin(got.len());
                Ok(())
            }
            .await;
            *STREAM.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        StreamRead
    }
}

#[test]
fn conn_stream_reads_a_direct_connection() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *STREAM.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        // Each write after the client has parked, so each read arms a receive.
        std::thread::sleep(Duration::from_millis(200));
        s.write_all(b"hello").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        s.write_all(b"world").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = std::io::Read::read(&mut s, &mut [0u8; 1]);
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<StreamRead>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        STREAM
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

static UNIX_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);
static UNIX: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// A connection from `connect_unix` is direct and reads what the peer sent.
struct UnixRead;

impl AsyncEventHandler for UnixRead {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = UNIX_PATH.lock().unwrap().clone().unwrap();
            let r = async {
                let mut conn = ringline::connect_unix(&path)
                    .await
                    .map_err(|e| format!("connect_unix: {e}"))?;
                if !conn.is_recv_direct() {
                    return Err("a connect_unix connection is not direct".into());
                }
                let mut got = Vec::new();
                while got.len() < 5 {
                    let n = ringline::timeout(
                        Duration::from_secs(2),
                        conn.with_data(|b| {
                            got.extend_from_slice(b);
                            ParseResult::Consumed(b.len())
                        }),
                    )
                    .await
                    .map_err(|_| "with_data did not resolve".to_string())?;
                    if n == 0 {
                        break;
                    }
                }
                if got != b"hello" {
                    return Err(format!("read {got:?}"));
                }
                Ok(())
            }
            .await;
            *UNIX.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        UnixRead
    }
}

#[test]
fn a_unix_connection_receives_directly() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("ringline-recv-direct-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sock");
    let _ = std::fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    *UNIX_PATH.lock().unwrap() = Some(path.clone());
    *UNIX.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        // After the client has parked, so the read arms a receive.
        std::thread::sleep(Duration::from_millis(200));
        s.write_all(b"hello").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = std::io::Read::read(&mut s, &mut [0u8; 1]);
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<UnixRead>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        UNIX.lock().unwrap().take().expect("client did not finish"),
        Ok(())
    );
}

static FWD_SINK: Mutex<Option<SocketAddr>> = Mutex::new(None);
static FORWARD: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Bytes the source peer sends before closing.
const FWD_TOTAL: usize = 100_000;
/// The first forward's length, short of `FWD_TOTAL`.
const FWD_FIRST: usize = 60_000;

/// Forward from a direct connection: a forward of `FWD_FIRST` bytes stops
/// there and leaves the rest readable, and a forward asking for more than
/// the peer sends resolves with what arrived before its FIN.
struct DirectForwardClient;

impl AsyncEventHandler for DirectForwardClient {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let source_addr = SERVER.lock().unwrap().unwrap();
            let sink_addr = FWD_SINK.lock().unwrap().unwrap();
            let r = async {
                let mut source = ringline::connect(source_addr)
                    .await
                    .map_err(|e| format!("connect source: {e}"))?;
                let sink = ringline::connect(sink_addr)
                    .await
                    .map_err(|e| format!("connect sink: {e}"))?;
                // A forward that is dropped leaves the source free for another.
                {
                    let spare = ringline::connect(sink_addr)
                        .await
                        .map_err(|e| format!("connect spare sink: {e}"))?;
                    let (mut spare_tx, _spare_rx) = spare.split();
                    drop(source.forward_to_conn(&mut spare_tx, 1));
                    match source.forward_to_conn(&mut spare_tx, 0).await {
                        Ok(0) => {}
                        other => return Err(format!("forward after drop: {other:?}")),
                    }
                }
                let (mut sink_tx, _sink_rx) = sink.split();
                let n = ringline::timeout(
                    Duration::from_secs(5),
                    source.forward_to_conn(&mut sink_tx, FWD_FIRST),
                )
                .await
                .map_err(|_| "first forward did not resolve".to_string())?
                .map_err(|e| format!("first forward: {e}"))?;
                if n != FWD_FIRST {
                    return Err(format!("first forward moved {n}"));
                }
                // The next byte is the first one the forward left.
                let mut first = None;
                source
                    .with_data(|b| {
                        first = b.first().copied();
                        ParseResult::Consumed(1)
                    })
                    .await;
                if first != Some(pattern(0, FWD_FIRST)) {
                    return Err(format!("byte after the forward: {first:?}"));
                }
                let n = ringline::timeout(
                    Duration::from_secs(5),
                    source.forward_to_conn(&mut sink_tx, FWD_TOTAL),
                )
                .await
                .map_err(|_| "second forward did not resolve".to_string())?
                .map_err(|e| format!("second forward: {e}"))?;
                if n != FWD_TOTAL - FWD_FIRST - 1 {
                    return Err(format!("second forward moved {n}"));
                }
                Ok(())
            }
            .await;
            *FORWARD.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        DirectForwardClient
    }
}

#[test]
fn a_direct_connection_forwards_to_another_connection() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let source = TcpListener::bind("127.0.0.1:0").unwrap();
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(source.local_addr().unwrap());
    *FWD_SINK.lock().unwrap() = Some(sink.local_addr().unwrap());
    *FORWARD.lock().unwrap() = None;
    let source_peer = std::thread::spawn(move || {
        let (mut s, _) = source.accept().unwrap();
        let data: Vec<u8> = (0..FWD_TOTAL).map(|i| pattern(0, i)).collect();
        // In pieces, so the forward sees several receives.
        // A failed write means the client closed the connection; its result
        // says why.
        for piece in data.chunks(7_000) {
            if s.write_all(piece).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let sink_peer = std::thread::spawn(move || {
        let (mut s, _) = sink.accept().unwrap();
        // The spare sink of the EBUSY check; it receives nothing.
        let (_spare, _) = sink.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 16_384];
        // Read until the client closes: closing first would close the sink
        // connection while the forward still waits for the source's FIN.
        loop {
            match std::io::Read::read(&mut s, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        got
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<DirectForwardClient>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    source_peer.join().unwrap();
    let got = sink_peer.join().unwrap();
    assert_eq!(
        FORWARD
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
    // Everything but the one byte read between the forwards, in order.
    let want: Vec<u8> = (0..FWD_TOTAL)
        .filter(|&i| i != FWD_FIRST)
        .map(|i| pattern(0, i))
        .collect();
    assert_eq!(got.len(), want.len());
    assert!(got == want, "the sink received the bytes out of order");
}

// ── Peer close on a connection nobody reads ─────────────────────────

static HANGUP: Mutex<Option<Result<(), String>>> = Mutex::new(None);
static HANGUP_SERVERS: Mutex<Vec<SocketAddr>> = Mutex::new(Vec::new());

/// Bytes the second server writes before it closes: several 32 KiB
/// receives' worth, and less than a loopback receive buffer, so the write
/// completes while the client does not read.
const HANGUP_TAIL: usize = 100_000;

/// Connects to each server and does not read. The first server closes at
/// once: that connection must stop being alive. The second writes
/// `HANGUP_TAIL` bytes and then closes: that connection stays alive while
/// its bytes are unread, then reads every byte and the end of the stream.
struct IdleClient;

impl AsyncEventHandler for IdleClient {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addrs = HANGUP_SERVERS.lock().unwrap().clone();
            let r = async {
                let empty = ringline::connect(addrs[0])
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut tail = ringline::connect(addrs[1])
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut closed = false;
                for _ in 0..500 {
                    if !empty.is_alive() {
                        closed = true;
                        break;
                    }
                    ringline::sleep(Duration::from_millis(10)).await;
                }
                if !closed {
                    return Err("the empty connection is alive 5 s after the peer closed".into());
                }
                // The tail's peer closed long ago; its bytes are still unread.
                ringline::sleep(Duration::from_millis(200)).await;
                if !tail.is_alive() {
                    return Err("the connection closed with its bytes unread".into());
                }
                let mut got = Vec::new();
                loop {
                    let n = tail
                        .with_data(|b| {
                            got.extend_from_slice(b);
                            ParseResult::Consumed(b.len())
                        })
                        .await;
                    if n == 0 {
                        break;
                    }
                }
                let want: Vec<u8> = (0..HANGUP_TAIL).map(|i| pattern(2, i)).collect();
                if got != want {
                    return Err(format!(
                        "read {} bytes, not the {HANGUP_TAIL} sent",
                        got.len()
                    ));
                }
                Ok(())
            }
            .await;
            *HANGUP.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        IdleClient
    }
}

#[test]
fn a_connection_that_is_not_read_sees_the_peer_close() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *HANGUP.lock().unwrap() = None;
    let mut servers = Vec::new();
    let mut addrs = Vec::new();
    for tail in [0, HANGUP_TAIL] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        addrs.push(listener.local_addr().unwrap());
        servers.push(std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            let data: Vec<u8> = (0..tail).map(|i| pattern(2, i)).collect();
            let _ = s.write_all(&data);
        }));
    }
    *HANGUP_SERVERS.lock().unwrap() = addrs;
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<IdleClient>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    for s in servers {
        s.join().unwrap();
    }
    assert_eq!(
        HANGUP
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

// ── Forward from a source whose peer closes ─────────────────────────

static SLOW_SINK: Mutex<Option<SocketAddr>> = Mutex::new(None);
static SLOW_FORWARD: Mutex<Option<Result<usize, String>>> = Mutex::new(None);

/// Bytes the source peer writes before it closes: more than one 32 KiB
/// receive, and less than a loopback receive buffer, so the FIN arrives
/// behind them before the forward starts.
const SLOW_TOTAL: usize = 64 * 1024;

/// Forwards `SLOW_TOTAL` bytes from a source whose peer has already written
/// them and closed: the hangup poll completes while nothing reads the
/// source and its bytes are still queued in the socket.
struct SlowSinkForward;

impl AsyncEventHandler for SlowSinkForward {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let source_addr = SERVER.lock().unwrap().unwrap();
            let sink_addr = SLOW_SINK.lock().unwrap().unwrap();
            let r = async {
                let mut source = ringline::connect(source_addr)
                    .await
                    .map_err(|e| format!("connect source: {e}"))?;
                let sink = ringline::connect(sink_addr)
                    .await
                    .map_err(|e| format!("connect sink: {e}"))?;
                let (mut sink_tx, _sink_rx) = sink.split();
                ringline::sleep(Duration::from_millis(50)).await;
                ringline::timeout(
                    Duration::from_secs(20),
                    source.forward_to_conn(&mut sink_tx, SLOW_TOTAL),
                )
                .await
                .map_err(|_| "the forward did not resolve".to_string())?
                .map_err(|e| format!("forward: {e}"))
            }
            .await;
            *SLOW_FORWARD.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        SlowSinkForward
    }
}

#[test]
fn a_forward_delivers_every_byte_after_the_source_peer_closed() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let source = TcpListener::bind("127.0.0.1:0").unwrap();
    let sink = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(source.local_addr().unwrap());
    *SLOW_SINK.lock().unwrap() = Some(sink.local_addr().unwrap());
    *SLOW_FORWARD.lock().unwrap() = None;
    let source_peer = std::thread::spawn(move || {
        let (mut s, _) = source.accept().unwrap();
        let data: Vec<u8> = (0..SLOW_TOTAL).map(|i| pattern(3, i)).collect();
        let _ = s.write_all(&data);
    });
    let sink_peer = std::thread::spawn(move || {
        let (mut s, _) = sink.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let mut got = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match std::io::Read::read(&mut s, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        got
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<SlowSinkForward>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    source_peer.join().unwrap();
    let got = sink_peer.join().unwrap();
    assert_eq!(
        SLOW_FORWARD
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(SLOW_TOTAL)
    );
    let want: Vec<u8> = (0..SLOW_TOTAL).map(|i| pattern(3, i)).collect();
    assert_eq!(got.len(), SLOW_TOTAL);
    assert!(got == want, "the sink received the bytes out of order");
}

// ── Peer close with bytes already buffered ──────────────────────────

static BUFFERED_CLOSE: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Reads 10 of the peer's 1,000 bytes, so the rest are in the
/// accumulator, then sleeps while the peer closes. The connection stays
/// alive with those bytes unread, and the next reads return them and then
/// the end of the stream.
struct BufferedThenClose;

impl AsyncEventHandler for BufferedThenClose {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut got = Vec::new();
                while got.len() < 1000 {
                    let n = conn
                        .with_data(|b| {
                            if b.len() < 1000 {
                                return ParseResult::NeedMore;
                            }
                            got.extend_from_slice(&b[..10]);
                            ParseResult::Consumed(10)
                        })
                        .await;
                    if n == 0 {
                        return Err("EOF before the first 1,000 bytes".into());
                    }
                    if !got.is_empty() {
                        break;
                    }
                }
                ringline::sleep(Duration::from_millis(300)).await;
                if !conn.is_alive() {
                    return Err("the connection closed with bytes buffered".into());
                }
                loop {
                    let n = conn
                        .with_data(|b| {
                            got.extend_from_slice(b);
                            ParseResult::Consumed(b.len())
                        })
                        .await;
                    if n == 0 {
                        break;
                    }
                }
                let want: Vec<u8> = (0..1000).map(|i| pattern(4, i)).collect();
                if got != want {
                    return Err(format!("read {} bytes, not the 1,000 sent", got.len()));
                }
                Ok(())
            }
            .await;
            *BUFFERED_CLOSE.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BufferedThenClose
    }
}

#[test]
fn a_peer_close_keeps_buffered_bytes_readable() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *BUFFERED_CLOSE.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let data: Vec<u8> = (0..1000).map(|i| pattern(4, i)).collect();
        let _ = s.write_all(&data);
        std::thread::sleep(Duration::from_millis(100));
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<BufferedThenClose>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        BUFFERED_CLOSE
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

// ── Reset and end of stream after a hangup peek ─────────────────────

static RESET_AFTER: Mutex<Option<Result<(), String>>> = Mutex::new(None);
static READ_ONCE: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Set `SO_LINGER` to zero, so closing the socket sends a reset.
fn linger_zero(s: &std::net::TcpStream) {
    use std::os::fd::AsRawFd;
    let l = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    let r = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            &l as *const libc::linger as *const libc::c_void,
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(r, 0, "SO_LINGER");
}

/// Reads 10 of the peer's 1,000 bytes and sleeps while the peer resets the
/// connection. The rest of the bytes are still read, and the read after
/// them reports the reset, not a clean end of stream.
struct ResetAfterBuffered;

impl AsyncEventHandler for ResetAfterBuffered {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut got = Vec::new();
                conn.with_data(|b| {
                    if b.len() < 1000 {
                        return ParseResult::NeedMore;
                    }
                    got.extend_from_slice(&b[..10]);
                    ParseResult::Consumed(10)
                })
                .await;
                ringline::sleep(Duration::from_millis(300)).await;
                loop {
                    match conn
                        .with_data_result(|b| {
                            got.extend_from_slice(b);
                            ParseResult::Consumed(b.len())
                        })
                        .await
                    {
                        Ok(0) => return Err(format!("a clean end after {} bytes", got.len())),
                        Ok(_) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
                        Err(e) => return Err(format!("error: {e}")),
                    }
                }
                if got.len() != 1000 {
                    return Err(format!("read {} bytes before the reset", got.len()));
                }
                Ok(())
            }
            .await;
            *RESET_AFTER.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        ResetAfterBuffered
    }
}

#[test]
fn a_reset_after_buffered_bytes_is_reported_as_a_reset() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *RESET_AFTER.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let data = vec![7u8; 1000];
        let _ = s.write_all(&data);
        std::thread::sleep(Duration::from_millis(100));
        linger_zero(&s);
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<ResetAfterBuffered>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        RESET_AFTER
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

/// The peer writes 5 bytes and closes while the client does not read, so
/// the hangup peek finds them queued. The client reads them once and never
/// reads again; the connection must still stop being alive.
struct ReadOnceThenIdle;

impl AsyncEventHandler for ReadOnceThenIdle {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                ringline::sleep(Duration::from_millis(200)).await;
                let mut got = Vec::new();
                conn.with_data(|b| {
                    got.extend_from_slice(b);
                    ParseResult::Consumed(b.len())
                })
                .await;
                if got != b"hello" {
                    return Err(format!("read {got:?}"));
                }
                for _ in 0..200 {
                    if !conn.is_alive() {
                        return Ok(());
                    }
                    ringline::sleep(Duration::from_millis(10)).await;
                }
                Err("alive 2 s after the last byte was read".into())
            }
            .await;
            *READ_ONCE.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        ReadOnceThenIdle
    }
}

#[test]
fn the_end_behind_queued_bytes_closes_a_connection_read_once() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *READ_ONCE.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = s.write_all(b"hello");
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<ReadOnceThenIdle>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        READ_ONCE
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

// ── End of stream behind buffered bytes ─────────────────────────────

static BUFFERED_READ_ONCE: Mutex<Option<Result<(), String>>> = Mutex::new(None);
static TICKLESS_READ_ONCE: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Consumes 2 of the peer's 5 bytes, sleeps while the peer closes (so the
/// hangup peek finds the other 3 buffered and nothing queued), reads the 3
/// once and never reads again. The connection must still stop being alive.
struct BufferedReadOnce;

impl AsyncEventHandler for BufferedReadOnce {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut got = Vec::new();
                conn.with_data(|b| {
                    if b.len() < 5 {
                        return ParseResult::NeedMore;
                    }
                    got.extend_from_slice(&b[..2]);
                    ParseResult::Consumed(2)
                })
                .await;
                ringline::sleep(Duration::from_millis(300)).await;
                conn.with_data(|b| {
                    got.extend_from_slice(b);
                    ParseResult::Consumed(b.len())
                })
                .await;
                if got != b"hello" {
                    return Err(format!("read {got:?}"));
                }
                for _ in 0..200 {
                    if !conn.is_alive() {
                        return Ok(());
                    }
                    ringline::sleep(Duration::from_millis(10)).await;
                }
                Err("alive 2 s after the last byte was read".into())
            }
            .await;
            *BUFFERED_READ_ONCE.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        BufferedReadOnce
    }
}

#[test]
fn the_end_behind_buffered_bytes_closes_a_connection_read_once() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *BUFFERED_READ_ONCE.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = s.write_all(b"hello");
        std::thread::sleep(Duration::from_millis(100));
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<BufferedReadOnce>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        BUFFERED_READ_ONCE
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

/// With `tick_timeout_us(0)` the worker blocks until a completion. The
/// peer writes 5 bytes and closes while the client does not read; the
/// client reads them once, sleeps once and checks: the recheck must have
/// run before the worker blocked, not at an unrelated later completion.
struct TicklessReadOnce;

impl AsyncEventHandler for TicklessReadOnce {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                ringline::sleep(Duration::from_millis(200)).await;
                conn.with_data(|b| ParseResult::Consumed(b.len())).await;
                ringline::sleep(Duration::from_millis(500)).await;
                if conn.is_alive() {
                    return Err("alive 500 ms after the read".into());
                }
                Ok(())
            }
            .await;
            *TICKLESS_READ_ONCE.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        TicklessReadOnce
    }
}

#[test]
fn a_recheck_runs_before_a_tickless_worker_blocks() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *TICKLESS_READ_ONCE.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = s.write_all(b"hello");
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .tick_timeout_us(0)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<TicklessReadOnce>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        TICKLESS_READ_ONCE
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

static RESET_READ_ONCE: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// Reads 10 of the peer's 1,000 bytes and sleeps while the peer resets the
/// connection, so the hangup peek takes the reset with 990 bytes buffered.
/// Reads those once without parking again; the recheck peek then finds the
/// end, the connection closes, and the next read reports the reset.
struct ResetThenReadOnce;

impl AsyncEventHandler for ResetThenReadOnce {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut got = 0usize;
                conn.with_data(|b| {
                    if b.len() < 1000 {
                        return ParseResult::NeedMore;
                    }
                    got += 10;
                    ParseResult::Consumed(10)
                })
                .await;
                ringline::sleep(Duration::from_millis(300)).await;
                conn.with_data(|b| {
                    got += b.len();
                    ParseResult::Consumed(b.len())
                })
                .await;
                if got != 1000 {
                    return Err(format!("read {got} bytes"));
                }
                let mut closed = false;
                for _ in 0..200 {
                    if !conn.is_alive() {
                        closed = true;
                        break;
                    }
                    ringline::sleep(Duration::from_millis(10)).await;
                }
                if !closed {
                    return Err("alive 2 s after the last byte was read".into());
                }
                match conn.with_data_result(|_| ParseResult::NeedMore).await {
                    Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
                    other => Err(format!("after 1000: {other:?}")),
                }
            }
            .await;
            *RESET_READ_ONCE.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        ResetThenReadOnce
    }
}

#[test]
fn a_reset_behind_buffered_bytes_read_once_is_reported_as_a_reset() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *RESET_READ_ONCE.lock().unwrap() = None;
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = s.write_all(&[7u8; 1000]);
        std::thread::sleep(Duration::from_millis(100));
        linger_zero(&s);
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<ResetThenReadOnce>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    assert_eq!(
        RESET_READ_ONCE
            .lock()
            .unwrap()
            .take()
            .expect("client did not finish"),
        Ok(())
    );
}

// ── Accepted connections ────────────────────────────────────────────

static INBOUND: Mutex<Option<Result<(), String>>> = Mutex::new(None);

/// An accepted plaintext connection is direct: it reads a message larger
/// than its region in order, and answers it.
struct InboundEcho;

impl AsyncEventHandler for InboundEcho {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let r = async {
                if !conn.is_recv_direct() {
                    return Err("an accepted plaintext connection is not direct".to_string());
                }
                let mut got = Vec::new();
                while got.len() < FWD_TOTAL {
                    let n = conn
                        .with_bytes(|b| {
                            got.extend_from_slice(&b);
                            ParseResult::Consumed(b.len())
                        })
                        .await;
                    if n == 0 {
                        break;
                    }
                }
                let want: Vec<u8> = (0..FWD_TOTAL).map(|i| pattern(1, i)).collect();
                if got != want {
                    return Err(format!("read {} bytes, not the pattern", got.len()));
                }
                conn.send(b"done")
                    .map_err(|e| format!("send: {e}"))?
                    .await
                    .map_err(|e| format!("send: {e}"))?;
                Ok(())
            }
            .await;
            *INBOUND.lock().unwrap() = Some(r);
            let _ = ringline::request_shutdown();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        InboundEcho
    }
}

#[test]
fn an_accepted_plaintext_connection_receives_directly() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    *INBOUND.lock().unwrap() = None;
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<InboundEcho>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let client = std::thread::spawn(move || {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        let data: Vec<u8> = (0..FWD_TOTAL).map(|i| pattern(1, i)).collect();
        for piece in data.chunks(9_000) {
            if s.write_all(piece).is_err() {
                return Vec::new();
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut reply = [0u8; 4];
        match std::io::Read::read_exact(&mut s, &mut reply) {
            Ok(()) => reply.to_vec(),
            Err(_) => Vec::new(),
        }
    });
    common::join_workers(&runtime, handles);
    let reply = client.join().unwrap();
    assert_eq!(
        INBOUND
            .lock()
            .unwrap()
            .take()
            .expect("handler did not finish"),
        Ok(())
    );
    assert_eq!(reply, b"done");
}
