#![allow(clippy::manual_async_fn)]
//! Integration tests focused on the UDP path.
//!
//! These tests exercise the UDP API end-to-end on whichever backend is
//! compiled in. The io_uring backend uses multishot recvmsg + a send slot
//! ring; the mio backend uses synchronous `recv_from` / `send_to`. Both
//! paths funnel through the same `UdpCtx` API so the tests are
//! backend-agnostic except where noted.

use std::collections::HashSet;
use std::future::Future;
use std::net::{Ipv6Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ringline::{
    AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, UdpCtx, UdpSendError,
};

// ── Helpers ────────────────────────────────────────────────────────────

fn base_config() -> Config {
    let mut cfg = Config::default();
    cfg.worker.threads = 1;
    cfg.worker.pin_to_core = false;
    cfg.sq_entries = 64;
    cfg.recv_buffer.ring_size = 64;
    cfg.recv_buffer.buffer_size = 4096;
    cfg.max_connections = 64;
    cfg.send_copy_count = 64;
    cfg.standalone_task_capacity = 64;
    cfg.tick_timeout_us = 5_000;
    cfg
}

fn free_udp_port() -> u16 {
    // Bind a UDP socket to :0, read the port, drop the socket.
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

fn free_udp_port_v6() -> u16 {
    let s = std::net::UdpSocket::bind("[::1]:0").unwrap();
    s.local_addr().unwrap().port()
}

fn await_handler_started(flag: &AtomicUsize) {
    for _ in 0..400 {
        if flag.load(Ordering::SeqCst) > 0 {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("UDP handler did not start within timeout");
}

// Many tests share static slots since `on_udp_bind` is called once per worker
// per bound address and we want to plug per-test handler state into the
// running worker. Tests that use the same slot must run serially — gate
// them with this mutex.
static UDP_SLOT_LOCK: Mutex<()> = Mutex::new(());

// ── Echo handler used by most tests ────────────────────────────────────

struct UdpEcho {
    started: Arc<AtomicUsize>,
}

impl AsyncEventHandler for UdpEcho {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {}
    }

    fn create_for_worker(_id: usize) -> Self {
        UdpEcho {
            started: ECHO_STARTED.get_or_init(Default::default).clone(),
        }
    }

    fn on_udp_bind(&self, udp: UdpCtx) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let started = self.started.clone();
        Some(Box::pin(async move {
            started.fetch_add(1, Ordering::SeqCst);
            loop {
                let (data, peer) = udp.recv_from().await;
                // Loop until the send pool has room.
                loop {
                    match udp.send_to(peer, &data) {
                        Ok(()) => break,
                        Err(UdpSendError::PoolExhausted)
                        | Err(UdpSendError::SubmissionQueueFull) => {
                            udp.send_ready().await;
                        }
                        Err(_) => break,
                    }
                }
            }
        }))
    }
}

static ECHO_STARTED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

fn reset_echo_started() {
    let started = ECHO_STARTED.get_or_init(Default::default);
    started.store(0, Ordering::SeqCst);
}

// ── Tests: basic round-trip ────────────────────────────────────────────

#[test]
fn udp_basic_round_trip() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(base_config())
        .bind_udp(addr)
        .launch::<UdpEcho>()
        .expect("launch");

    await_handler_started(ECHO_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let payload = b"hello udp";
    client.send_to(payload, addr).unwrap();

    let mut buf = [0u8; 64];
    let (n, src) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload);
    assert_eq!(src, addr, "echo source mismatch");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

#[test]
fn udp_echo_many_datagrams_in_sequence() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(base_config())
        .bind_udp(addr)
        .launch::<UdpEcho>()
        .expect("launch");
    await_handler_started(ECHO_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let mut buf = [0u8; 1024];
    for i in 0..200u32 {
        let msg = format!("seq-{i}");
        client.send_to(msg.as_bytes(), addr).unwrap();
        let (n, _src) = client.recv_from(&mut buf).unwrap();
        assert_eq!(
            std::str::from_utf8(&buf[..n]).unwrap(),
            msg,
            "echoed payload mismatch on iteration {i}"
        );
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Multiple distinct clients (peer addr round-trip) ────────────────────

#[test]
fn udp_echo_distinguishes_peers() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(base_config())
        .bind_udp(addr)
        .launch::<UdpEcho>()
        .expect("launch");
    await_handler_started(ECHO_STARTED.get().unwrap());

    // Three clients, each gets its own message echoed to its own port.
    let clients: Vec<UdpSocket> = (0..3)
        .map(|_| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            s
        })
        .collect();

    for (i, c) in clients.iter().enumerate() {
        let m = format!("payload-{i}");
        c.send_to(m.as_bytes(), addr).unwrap();
    }

    let mut buf = [0u8; 64];
    for (i, c) in clients.iter().enumerate() {
        let (n, _) = c.recv_from(&mut buf).unwrap();
        let s = std::str::from_utf8(&buf[..n]).unwrap();
        assert_eq!(s, format!("payload-{i}"), "client {i} got wrong echo");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Burst send: clients send many packets back-to-back ──────────────────

#[test]
fn udp_echo_burst_unique_payloads() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut cfg = base_config();
    // Make sure send slot ring is comfortably larger than the burst so the
    // server doesn't have to wait on send_ready for the common case.
    cfg.udp_send_slots = 64;
    let (shutdown, handles) = RinglineBuilder::new(cfg)
        .bind_udp(addr)
        .launch::<UdpEcho>()
        .expect("launch");
    await_handler_started(ECHO_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let count = 100u32;
    for i in 0..count {
        let payload = format!("burst-{i:04}");
        client.send_to(payload.as_bytes(), addr).unwrap();
    }

    // Recv everything; the kernel may reorder but loopback usually preserves
    // order. We tolerate either by comparing as a multiset.
    let mut got = HashSet::new();
    let mut buf = [0u8; 128];
    while got.len() < count as usize {
        match client.recv_from(&mut buf) {
            Ok((n, _src)) => {
                let s = std::str::from_utf8(&buf[..n]).unwrap().to_string();
                got.insert(s);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => panic!("recv error: {e}"),
        }
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    let lost = count as usize - got.len();
    // Tolerate small loss on saturated loopback, but not catastrophic.
    assert!(
        lost <= 5,
        "lost {lost} of {count} echoes — too many; received={}",
        got.len()
    );
}

// ── Larger payloads near MTU ───────────────────────────────────────────

#[test]
fn udp_large_datagram_within_mtu() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // Bump the recv buffer to comfortably cover ~1400 bytes + header.
    let mut cfg = base_config();
    cfg.udp_recv_buffer.buffer_size = 4096;
    let (shutdown, handles) = RinglineBuilder::new(cfg)
        .bind_udp(addr)
        .launch::<UdpEcho>()
        .expect("launch");
    await_handler_started(ECHO_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let payload: Vec<u8> = (0u8..=255).cycle().take(1400).collect();
    client.send_to(&payload, addr).unwrap();

    let mut buf = vec![0u8; 4096];
    let (n, _src) = client.recv_from(&mut buf).unwrap();
    assert_eq!(n, payload.len(), "echoed length mismatch");
    assert_eq!(&buf[..n], payload.as_slice(), "echoed payload mismatch");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Multiple bound UDP addresses ────────────────────────────────────────

#[test]
fn udp_multiple_bound_sockets() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    let p1 = free_udp_port();
    let p2 = loop {
        let p = free_udp_port();
        if p != p1 {
            break p;
        }
    };
    let a1: SocketAddr = format!("127.0.0.1:{p1}").parse().unwrap();
    let a2: SocketAddr = format!("127.0.0.1:{p2}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(base_config())
        .bind_udp(a1)
        .bind_udp(a2)
        .launch::<UdpEcho>()
        .expect("launch");

    // Wait for both UDP handlers to start.
    let started = ECHO_STARTED.get_or_init(Default::default);
    for _ in 0..400 {
        if started.load(Ordering::SeqCst) >= 2 {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        started.load(Ordering::SeqCst) >= 2,
        "both UDP handlers should have started"
    );

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    for (addr, msg) in [(a1, b"to-port-1".as_ref()), (a2, b"to-port-2")] {
        client.send_to(msg, addr).unwrap();
        let mut buf = [0u8; 64];
        let (n, src) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], msg);
        assert_eq!(src, addr, "echo came from wrong socket");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── IPv6 ───────────────────────────────────────────────────────────────

#[test]
fn udp_ipv6_round_trip() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    // Skip if loopback IPv6 is unavailable in the test environment.
    let probe = match UdpSocket::bind("[::1]:0") {
        Ok(s) => s,
        Err(_) => return,
    };
    drop(probe);

    let port = free_udp_port_v6();
    let addr: SocketAddr = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port);

    let (shutdown, handles) = RinglineBuilder::new(base_config())
        .bind_udp(addr)
        .launch::<UdpEcho>()
        .expect("launch");
    await_handler_started(ECHO_STARTED.get().unwrap());

    let client = UdpSocket::bind("[::1]:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    let payload = b"v6 echo";
    client.send_to(payload, addr).unwrap();

    let mut buf = [0u8; 64];
    let (n, src) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], payload);
    assert_eq!(src.port(), port, "echo source port mismatch");
    assert!(src.is_ipv6(), "echo source not IPv6: {src}");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Send pool exhaustion / send_ready ──────────────────────────────────

/// Handler that never responds to incoming datagrams but spams `send_to` until
/// it sees `PoolExhausted`, awaits `send_ready`, then continues. We use this
/// to verify the ring-based send slot accounting.
struct SendStress {
    started: Arc<AtomicUsize>,
    saw_exhausted: Arc<AtomicUsize>,
    sent_ok: Arc<AtomicUsize>,
}

static SEND_STRESS_STARTED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static SEND_STRESS_EXHAUSTED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static SEND_STRESS_SENT: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static SEND_STRESS_PEER: OnceLock<Mutex<Option<SocketAddr>>> = OnceLock::new();

impl AsyncEventHandler for SendStress {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {}
    }
    fn create_for_worker(_id: usize) -> Self {
        SendStress {
            started: SEND_STRESS_STARTED.get_or_init(Default::default).clone(),
            saw_exhausted: SEND_STRESS_EXHAUSTED.get_or_init(Default::default).clone(),
            sent_ok: SEND_STRESS_SENT.get_or_init(Default::default).clone(),
        }
    }
    fn on_udp_bind(&self, udp: UdpCtx) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let started = self.started.clone();
        let saw_exhausted = self.saw_exhausted.clone();
        let sent_ok = self.sent_ok.clone();
        Some(Box::pin(async move {
            started.fetch_add(1, Ordering::SeqCst);
            // Wait for the test to learn our peer address from a probe message.
            let (_data, peer) = udp.recv_from().await;
            let _ = SEND_STRESS_PEER
                .get_or_init(|| Mutex::new(None))
                .lock()
                .unwrap()
                .replace(peer);
            // Now blast send_to and verify exhaustion paths work.
            let payload = b"x".repeat(64);
            // Send up to a fixed total; the slot ring is small so we expect
            // to hit PoolExhausted multiple times.
            for _ in 0..2_000u32 {
                loop {
                    match udp.send_to(peer, &payload) {
                        Ok(()) => {
                            sent_ok.fetch_add(1, Ordering::SeqCst);
                            break;
                        }
                        Err(UdpSendError::PoolExhausted) => {
                            saw_exhausted.fetch_add(1, Ordering::SeqCst);
                            udp.send_ready().await;
                        }
                        Err(UdpSendError::SubmissionQueueFull) => {
                            udp.send_ready().await;
                        }
                        Err(UdpSendError::Io(_)) => {
                            return;
                        }
                    }
                }
            }
        }))
    }
}

#[test]
fn udp_send_ready_unblocks_after_exhaustion() {
    // io_uring backend only — on mio the send is synchronous and PoolExhausted
    // means WouldBlock from the kernel, which only triggers under very
    // different conditions and isn't a meaningful exercise of `send_ready`.
    if ringline::backend() != ringline::Backend::IoUring {
        return;
    }
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    SEND_STRESS_STARTED
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);
    SEND_STRESS_EXHAUSTED
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);
    SEND_STRESS_SENT
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);
    let _ = SEND_STRESS_PEER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap()
        .take();

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut cfg = base_config();
    cfg.udp_send_slots = 4; // tiny ring → forces exhaustion

    let (shutdown, handles) = RinglineBuilder::new(cfg)
        .bind_udp(addr)
        .launch::<SendStress>()
        .expect("launch");
    await_handler_started(SEND_STRESS_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    // Probe so the server learns our address.
    client.send_to(b"hello", addr).unwrap();

    // Drain incoming traffic for a bit.
    let mut buf = vec![0u8; 4096];
    let mut received = 0u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match client.recv_from(&mut buf) {
            Ok(_) => received += 1,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Stop draining when the server quiesces or the cap is hit.
                let sent = SEND_STRESS_SENT
                    .get()
                    .map(|c| c.load(Ordering::SeqCst))
                    .unwrap_or(0);
                if sent >= 2_000 {
                    break;
                }
            }
            Err(e) => panic!("recv: {e}"),
        }
    }

    let exhausted = SEND_STRESS_EXHAUSTED.get().unwrap().load(Ordering::SeqCst);
    let sent = SEND_STRESS_SENT.get().unwrap().load(Ordering::SeqCst);
    assert!(
        sent >= 1_000,
        "server should have sent many datagrams; sent={sent}"
    );
    assert!(
        exhausted >= 5,
        "server should have observed PoolExhausted multiple times; \
         exhausted={exhausted}"
    );
    assert!(
        received >= 100,
        "client should have received many datagrams; received={received}"
    );

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Datagram larger than copy slot returns a recoverable error ─────────

/// Verifies that `send_to` with data larger than `send_copy_slot_size`
/// returns a *non-retryable* error (not `PoolExhausted` — that's a transient
/// condition that callers may wait out via `send_ready()`, and the
/// oversized case will never become retryable on its own). Also asserts
/// the socket remains usable for follow-up sends of normal size.
struct OversizedSend {
    started: Arc<AtomicUsize>,
    oversized_err: Arc<AtomicUsize>,
    follow_up_ok: Arc<AtomicUsize>,
}

static OVER_STARTED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static OVER_ERR: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static OVER_OK: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

impl AsyncEventHandler for OversizedSend {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {}
    }
    fn create_for_worker(_id: usize) -> Self {
        OversizedSend {
            started: OVER_STARTED.get_or_init(Default::default).clone(),
            oversized_err: OVER_ERR.get_or_init(Default::default).clone(),
            follow_up_ok: OVER_OK.get_or_init(Default::default).clone(),
        }
    }
    fn on_udp_bind(&self, udp: UdpCtx) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let started = self.started.clone();
        let oversized_err = self.oversized_err.clone();
        let follow_up_ok = self.follow_up_ok.clone();
        Some(Box::pin(async move {
            started.fetch_add(1, Ordering::SeqCst);
            let (_data, peer) = udp.recv_from().await;
            // Try to send something far bigger than send_copy_slot_size.
            let big = vec![0xAAu8; 32 * 1024];
            match udp.send_to(peer, &big) {
                Ok(()) => {} // would be wrong but let's not abort
                Err(UdpSendError::PoolExhausted) | Err(UdpSendError::SubmissionQueueFull) => {
                    // Wrong: oversize is a permanent condition, not a
                    // transient one. The handler intentionally does NOT
                    // count this case so the test fails loudly.
                }
                Err(UdpSendError::Io(_)) => {
                    oversized_err.fetch_add(1, Ordering::SeqCst);
                }
            }
            // Now send a normal payload; this must succeed.
            if udp.send_to(peer, b"after-oversized").is_ok() {
                follow_up_ok.fetch_add(1, Ordering::SeqCst);
            }
        }))
    }
}

#[test]
fn udp_oversized_send_does_not_corrupt_state() {
    // Only the io_uring backend funnels sends through `send_copy_pool`,
    // where oversize datagrams hit the slot-size limit and need an
    // explicit rejection. The mio backend hands the buffer straight to
    // the kernel, which happily accepts datagrams up to ~65 KiB on
    // loopback, so this scenario doesn't apply there.
    if ringline::backend() != ringline::Backend::IoUring {
        return;
    }
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    OVER_STARTED
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);
    OVER_ERR
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);
    OVER_OK
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut cfg = base_config();
    cfg.send_copy_slot_size = 4096; // smaller than the big payload
    cfg.udp_recv_buffer.buffer_size = 4096;
    let (shutdown, handles) = RinglineBuilder::new(cfg)
        .bind_udp(addr)
        .launch::<OversizedSend>()
        .expect("launch");
    await_handler_started(OVER_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();

    client.send_to(b"trigger", addr).unwrap();

    let mut buf = [0u8; 64];
    let (n, _src) = client.recv_from(&mut buf).unwrap();
    assert_eq!(
        &buf[..n],
        b"after-oversized",
        "follow-up datagram must arrive after the oversized send is rejected"
    );

    let oversized_err = OVER_ERR.get().unwrap().load(Ordering::SeqCst);
    let follow_up_ok = OVER_OK.get().unwrap().load(Ordering::SeqCst);
    assert_eq!(oversized_err, 1, "oversized send must return Err");
    assert_eq!(follow_up_ok, 1, "follow-up send must succeed");

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Recv buffer truncation: payload larger than UDP recv buffer ────────

/// When a peer sends a datagram bigger than the UDP recv buffer can hold,
/// the multishot recvmsg sets the `payload_truncated` flag. The handler
/// silently drops the datagram (parser sees truncated msg). We verify that
/// the socket *remains live* — the next non-truncated datagram still gets
/// echoed.
struct CountingEcho {
    started: Arc<AtomicUsize>,
    received: Arc<AtomicU64>,
}

static COUNT_STARTED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static COUNT_RECV: OnceLock<Arc<AtomicU64>> = OnceLock::new();

impl AsyncEventHandler for CountingEcho {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {}
    }
    fn create_for_worker(_id: usize) -> Self {
        CountingEcho {
            started: COUNT_STARTED.get_or_init(Default::default).clone(),
            received: COUNT_RECV.get_or_init(Default::default).clone(),
        }
    }
    fn on_udp_bind(&self, udp: UdpCtx) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let started = self.started.clone();
        let received = self.received.clone();
        Some(Box::pin(async move {
            started.fetch_add(1, Ordering::SeqCst);
            loop {
                let (data, peer) = udp.recv_from().await;
                received.fetch_add(1, Ordering::SeqCst);
                let _ = udp.send_to(peer, &data);
            }
        }))
    }
}

#[test]
fn udp_truncated_datagram_recoverable() {
    if ringline::backend() != ringline::Backend::IoUring {
        // Only the io_uring backend uses a fixed-size provided buffer per
        // datagram. mio's recv path uses a 64KiB stack buffer that always
        // fits the payload, so there's nothing to truncate.
        return;
    }
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    COUNT_STARTED
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);
    COUNT_RECV
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    // Tight recv buffer: 256 bytes total → ~70 bytes for payload after the
    // io_uring header + sockaddr.
    let mut cfg = base_config();
    cfg.udp_recv_buffer.buffer_size = 256;
    cfg.udp_recv_buffer.ring_size = 16;
    let (shutdown, handles) = RinglineBuilder::new(cfg)
        .bind_udp(addr)
        .launch::<CountingEcho>()
        .expect("launch");
    await_handler_started(COUNT_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();

    // Send an oversized datagram that *will* be truncated server-side.
    let big = vec![0xCDu8; 1500];
    client.send_to(&big, addr).unwrap();
    // Server must drop it; client should receive nothing.
    let mut buf = vec![0u8; 4096];
    match client.recv_from(&mut buf) {
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut => {}
        Ok((n, _)) => panic!("did not expect echo of truncated datagram, got {n} bytes"),
        Err(e) => panic!("unexpected recv error: {e}"),
    }

    // Now send a small one; it must round-trip — i.e. the multishot was
    // rearmed properly after the truncated datagram fed back through the
    // ring.
    let small = b"small";
    client.send_to(small, addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let (n, _src) = client.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], small);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── Multi-worker UDP via SO_REUSEPORT ──────────────────────────────────

/// Each worker gets its own UDP socket bound to the same address with
/// SO_REUSEPORT. The kernel hashes incoming datagrams across workers.
/// Our echo handler reports its worker_id in the response so we can verify
/// that more than one worker actually got traffic.
struct ReuseportEcho {
    worker_id: usize,
    started: Arc<AtomicUsize>,
}

static REUSE_STARTED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

impl AsyncEventHandler for ReuseportEcho {
    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {}
    }
    fn create_for_worker(id: usize) -> Self {
        ReuseportEcho {
            worker_id: id,
            started: REUSE_STARTED.get_or_init(Default::default).clone(),
        }
    }
    fn on_udp_bind(&self, udp: UdpCtx) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let worker_id = self.worker_id;
        let started = self.started.clone();
        Some(Box::pin(async move {
            started.fetch_add(1, Ordering::SeqCst);
            loop {
                let (mut data, peer) = udp.recv_from().await;
                data.push(b':');
                data.extend_from_slice(format!("{worker_id}").as_bytes());
                loop {
                    match udp.send_to(peer, &data) {
                        Ok(()) => break,
                        Err(UdpSendError::PoolExhausted)
                        | Err(UdpSendError::SubmissionQueueFull) => {
                            udp.send_ready().await;
                        }
                        Err(_) => break,
                    }
                }
            }
        }))
    }
}

#[test]
fn udp_reuseport_balances_across_workers() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    REUSE_STARTED
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let mut cfg = base_config();
    cfg.worker.threads = 4;
    let workers = cfg.worker.threads;

    let (shutdown, handles) = RinglineBuilder::new(cfg)
        .bind_udp(addr)
        .launch::<ReuseportEcho>()
        .expect("launch");

    let started = REUSE_STARTED.get().unwrap();
    for _ in 0..400 {
        if started.load(Ordering::SeqCst) >= workers {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        started.load(Ordering::SeqCst),
        workers,
        "all workers should have started UDP handlers"
    );

    // Give each worker many distinct source ports so the kernel hash spreads
    // datagrams. A single source/dest tuple usually sticks to one worker.
    let mut clients: Vec<UdpSocket> = Vec::new();
    for _ in 0..32 {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        clients.push(s);
    }

    for c in &clients {
        c.send_to(b"x", addr).unwrap();
    }

    let mut workers_seen: HashSet<usize> = HashSet::new();
    let mut buf = [0u8; 64];
    for c in &clients {
        if let Ok((n, _src)) = c.recv_from(&mut buf) {
            // payload is "x:<worker_id>"
            let s = std::str::from_utf8(&buf[..n]).unwrap();
            let id: usize = s
                .strip_prefix("x:")
                .and_then(|t| t.parse().ok())
                .unwrap_or(usize::MAX);
            workers_seen.insert(id);
        }
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }

    assert!(
        workers_seen.len() >= 2,
        "REUSEPORT failed to spread across workers; only {workers_seen:?} echoed"
    );
}

// ── Empty (zero-byte) datagram ─────────────────────────────────────────

/// Verifies that a UDP socket can echo zero-length datagrams (a legal
/// thing on the wire) without dropping them. Some recvmsg implementations
/// confuse `result == 0` with EOF; the io_uring multishot path uses a
/// composite header so the CQE result is always non-zero on success — but
/// we want a regression test in case future refactors break that.
#[test]
fn udp_echo_zero_byte_datagram() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    reset_echo_started();

    let port = free_udp_port();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(base_config())
        .bind_udp(addr)
        .launch::<UdpEcho>()
        .expect("launch");
    await_handler_started(ECHO_STARTED.get().unwrap());

    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.send_to(&[], addr).unwrap();

    let mut buf = [0u8; 16];
    let (n, src) = client.recv_from(&mut buf).unwrap();
    assert_eq!(n, 0, "echoed datagram should be empty");
    assert_eq!(src, addr);

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

// ── TCP + UDP coexistence ──────────────────────────────────────────────

struct TcpUdpHandler {
    started: Arc<AtomicUsize>,
}

static TCP_UDP_STARTED: OnceLock<Arc<AtomicUsize>> = OnceLock::new();

impl AsyncEventHandler for TcpUdpHandler {
    fn on_accept(&self, conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        let _ = conn.send_nowait(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        TcpUdpHandler {
            started: TCP_UDP_STARTED.get_or_init(Default::default).clone(),
        }
    }
    fn on_udp_bind(&self, udp: UdpCtx) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let started = self.started.clone();
        Some(Box::pin(async move {
            started.fetch_add(1, Ordering::SeqCst);
            loop {
                let (data, peer) = udp.recv_from().await;
                let _ = udp.send_to(peer, &data);
            }
        }))
    }
}

#[test]
fn udp_and_tcp_coexist() {
    let _guard = UDP_SLOT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    TCP_UDP_STARTED
        .get_or_init(Default::default)
        .store(0, Ordering::SeqCst);

    let tcp_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let udp_port = free_udp_port();
    let tcp_addr: SocketAddr = format!("127.0.0.1:{tcp_port}").parse().unwrap();
    let udp_addr: SocketAddr = format!("127.0.0.1:{udp_port}").parse().unwrap();

    let (shutdown, handles) = RinglineBuilder::new(base_config())
        .bind(tcp_addr)
        .bind_udp(udp_addr)
        .launch::<TcpUdpHandler>()
        .expect("launch");

    // Wait for both TCP listener and UDP handler.
    await_handler_started(TCP_UDP_STARTED.get().unwrap());
    for _ in 0..200 {
        if std::net::TcpStream::connect(tcp_addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // TCP echo.
    {
        use std::io::{Read, Write};
        let mut s = std::net::TcpStream::connect(tcp_addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(b"tcp-msg").unwrap();
        let mut buf = [0u8; 32];
        let n = s.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"tcp-msg");
    }

    // UDP echo.
    {
        let c = UdpSocket::bind("127.0.0.1:0").unwrap();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        c.send_to(b"udp-msg", udp_addr).unwrap();
        let mut buf = [0u8; 32];
        let (n, _) = c.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"udp-msg");
    }

    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
