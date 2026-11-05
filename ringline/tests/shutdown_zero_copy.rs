//! A zero-copy send in flight at worker exit (#607). A peer that does not read
//! keeps the data queued, so its notification never lands. Exit closes that
//! connection with an RST after about 1 s, on Linux 6.7+. A peer that reads in
//! that time gets what the kernel had queued, and a FIN.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
};

/// Larger than the loopback socket buffers hold, and small enough to fit under
/// an 8 MiB `RLIMIT_MEMLOCK`.
const GUARD_LEN: usize = 4 << 20;

static SENT: AtomicBool = AtomicBool::new(false);

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

/// Waits for one byte, sends a guarded body, and keeps the connection open.
struct GuardSender;

impl AsyncEventHandler for GuardSender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            let guard = GuardBox::new(VecGuard(vec![7; GUARD_LEN]));
            conn.send_parts()
                .build(|b| b.guard(guard).submit())
                .expect("guard send accepted");
            SENT.store(true, Ordering::SeqCst);
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        GuardSender
    }
}

fn kernel_has_setsockopt_command() -> bool {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut uts) }, 0);
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    (parts.next().unwrap_or(0), parts.next().unwrap_or(0)) >= (6, 7)
}

/// Launch, make the server send, and return the runtime and a connected peer
/// that has not read.
fn server_with_a_send_in_flight() -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
    TcpStream,
) {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<GuardSender>()
        .expect("launch");
    let mut peer = TcpStream::connect(runtime.bound_addr().expect("bound")).expect("connect");
    peer.write_all(b"x").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !SENT.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(SENT.load(Ordering::SeqCst), "the send never started");
    std::thread::sleep(Duration::from_millis(50));
    (runtime, handles, peer)
}

#[test]
fn exit_does_not_wait_for_a_peer_that_does_not_read() {
    let (runtime, handles, peer) = server_with_a_send_in_flight();
    let started = Instant::now();
    runtime.shutdown();
    for handle in handles {
        handle.join().expect("worker panicked").expect("worker");
    }
    let took = started.elapsed();
    if kernel_has_setsockopt_command() {
        // A short exit means no zero-copy send was held: over `RLIMIT_MEMLOCK`
        // it falls back to plain sends, and there is nothing to test.
        let enomem = ringline::metrics::POOL
            .value(ringline::metrics::pool::SEND_ZC_ENOMEM)
            .unwrap_or(0);
        if enomem == 0 {
            assert!(took >= Duration::from_millis(900), "not held: {took:?}");
        }
        assert!(took < Duration::from_secs(4), "worker exit took {took:?}");
        if enomem == 0 {
            let mut peer = peer;
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut body = Vec::new();
            let read = peer.read_to_end(&mut body);
            assert!(
                matches!(&read, Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset),
                "the stuck connection was not reset: {read:?}"
            );
        }
    }
}

/// Exit cancels the send, so the peer gets what the kernel had queued. The close
/// that follows is a FIN: an RST here would discard that data.
#[test]
fn a_peer_that_reads_during_exit_sees_a_clean_close() {
    let (runtime, handles, mut peer) = server_with_a_send_in_flight();
    runtime.shutdown();
    // Well inside the grace period.
    std::thread::sleep(Duration::from_millis(200));
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut body = Vec::new();
    peer.read_to_end(&mut body).expect("a clean close");
    assert!(!body.is_empty());
    assert!(body.iter().all(|&b| b == 7));
    for handle in handles {
        handle.join().expect("worker panicked").expect("worker");
    }
}
