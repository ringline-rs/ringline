//! A peer whose data arrives faster than its reader drains it (a reader that
//! never reads, a forward whose peer never reads the reply) is stopped by its
//! own TCP window, and another connection on the same worker keeps working.
//! The accepted connections here are plaintext, so they receive directly: a
//! receive is armed when a read parks, and a reader that does not read takes
//! nothing off the socket.
#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// The first byte picks the mode: `N` never reads again, `R` echoes each
/// buffer with `forward_recv_buf`, `T` echoes with `forward_to_conn`, and
/// anything else echoes through `with_data`.
struct Modes;

impl AsyncEventHandler for Modes {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut first = 0u8;
            let n = conn
                .with_data(|d| {
                    first = d[0];
                    ParseResult::Consumed(1)
                })
                .await;
            if n == 0 {
                return;
            }
            match first {
                b'N' => loop {
                    ringline::sleep(Duration::from_secs(1)).await;
                },
                b'R' => {
                    let (mut tx, mut rx) = conn.split();
                    loop {
                        let n = rx
                            .with_data(|d| match tx.forward_recv_buf(d) {
                                Ok(()) => ParseResult::Consumed(d.len()),
                                Err(_) => ParseResult::NeedMore,
                            })
                            .await;
                        if n == 0 {
                            break;
                        }
                    }
                }
                b'T' => {
                    let (mut tx, mut rx) = conn.split();
                    while rx.forward_to_conn(&mut tx, 1 << 20).await.is_ok() {}
                }
                _ => {
                    let (mut tx, mut rx) = conn.split();
                    loop {
                        let n = rx
                            .with_data(|d| {
                                let _ = tx.send_nowait(d);
                                ParseResult::Consumed(d.len())
                            })
                            .await;
                        if n == 0 {
                            break;
                        }
                    }
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Modes
    }
}

/// Flood a connection in mode `mode` without reading from it, then check
/// that its writes stalled and that an echo connection on the same worker
/// still answers.
fn idle_peer_is_throttled_alone(mode: u8) {
    idle_peers_are_throttled_alone(mode, 1);
}

/// A connection in mode `R` echoes an 8 KiB message, which takes a send slab
/// entry, so it fails if the idle peers have exhausted the slab.
fn forward_echo_works(addr: std::net::SocketAddr) -> bool {
    let message = vec![9u8; 8192];
    let mut peer = TcpStream::connect(addr).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    peer.write_all(b"R").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    peer.write_all(&message).unwrap();
    let mut echoed = vec![0u8; message.len()];
    peer.read_exact(&mut echoed).is_ok() && echoed == message
}

/// `idle_peer_is_throttled_alone` with `peers` idle connections in mode
/// `mode`, each flooded in turn.
fn idle_peers_are_throttled_alone(mode: u8, peers: usize) {
    const LIMIT: u64 = 64 << 20;
    let mut config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(64)
        .send_pool(64, 16384);
    if mode == b'R' {
        // Over half used at 33 entries, so three held peers leave room.
        config = config.send_slab_slots(64).forward_hold_cap(8);
    }
    let config = config.build().expect("config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Modes>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");
    std::thread::sleep(Duration::from_millis(100));

    let chunk = vec![7u8; 1 << 20];
    let mut idle = Vec::new();
    let mut most = 0u64;
    for _ in 0..peers {
        let mut peer = TcpStream::connect(addr).unwrap();
        peer.write_all(&[mode]).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        peer.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut sent = 0u64;
        while sent < LIMIT {
            match peer.write(&chunk) {
                Ok(n) => sent += n as u64,
                Err(_) => break,
            }
        }
        most = most.max(sent);
        idle.push(peer);
    }

    let mut other = TcpStream::connect(addr).unwrap();
    other
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    other.write_all(b"Eping").unwrap();
    let mut buf = [0u8; 4];
    let echoed = other.read_exact(&mut buf).is_ok() && &buf == b"ping";
    let forwarded = forward_echo_works(addr);

    drop(idle);
    drop(other);
    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
    let label = format!("mode {}, {peers} idle", mode as char);
    assert!(
        most < LIMIT,
        "{label}: the server accepted {most} bytes unread"
    );
    assert!(echoed, "{label}: another connection on the worker stalled");
    assert!(forwarded, "{label}: a guarded send on the worker failed");
}

/// A reader that never reads arms no receive, so its peer's writes stall.
#[test]
fn an_idle_reader_is_throttled_alone() {
    idle_peer_is_throttled_alone(b'N');
}

/// A `forward_to_conn` from a direct connection stops receiving while its
/// sends to a peer that does not read are stuck, so that peer's writes
/// stall.
#[test]
fn unread_forward_to_peers_are_throttled_alone() {
    idle_peers_are_throttled_alone(b'T', 3);
}

/// A connection that forwards each buffer with `forward_recv_buf` stops
/// receiving once its sends to a peer that does not read are queued to the
/// hold cap, so that peer's writes stall (#733).
#[test]
fn an_unread_forward_recv_buf_is_throttled_alone() {
    idle_peer_is_throttled_alone(b'R');
}

/// Several such peers on one worker, which share its send slab.
#[test]
fn unread_forward_recv_bufs_are_throttled_alone() {
    idle_peers_are_throttled_alone(b'R', 3);
}

/// A peer that closes during a hold fails its queued sends, which releases their
/// slab entries, so the held read sees the close and the task ends.
#[test]
fn a_held_forward_recv_buf_ends_when_its_peer_closes() {
    static ENDED: AtomicBool = AtomicBool::new(false);

    struct EndFlag;
    impl Drop for EndFlag {
        fn drop(&mut self) {
            ENDED.store(true, Ordering::SeqCst);
        }
    }

    struct Handler;
    impl AsyncEventHandler for Handler {
        fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
            async move {
                let _ended = EndFlag;
                let (mut tx, mut rx) = conn.split();
                loop {
                    let n = rx
                        .with_data(|d| match tx.forward_recv_buf(d) {
                            Ok(()) => ParseResult::Consumed(d.len()),
                            Err(_) => ParseResult::NeedMore,
                        })
                        .await;
                    if n == 0 {
                        break;
                    }
                }
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            Handler
        }
    }

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(64)
        .send_pool(64, 16384)
        .send_slab_slots(8)
        .forward_hold_cap(2)
        .build()
        .expect("config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");

    let mut peer = TcpStream::connect(addr).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let chunk = vec![7u8; 1 << 20];
    let mut sent = 0u64;
    while sent < 64 << 20 {
        match peer.write(&chunk) {
            Ok(n) => sent += n as u64,
            Err(_) => break,
        }
    }
    assert!(sent < 64 << 20, "the connection was not held");
    drop(peer);

    let deadline = Instant::now() + Duration::from_secs(10);
    while !ENDED.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let ended = ENDED.load(Ordering::SeqCst);
    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
    assert!(ended, "the read stayed parked after its peer closed");
}

/// A peer that writes a large batch before reading any of it is not stuck. With
/// the slab under half used it is not held, so the batch completes.
#[test]
fn a_lone_peer_can_write_a_batch_before_reading() {
    const TOTAL: usize = 8 << 20;
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(64)
        .send_pool(64, 16384)
        .build()
        .expect("config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Modes>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");

    let mut peer = TcpStream::connect(addr).unwrap();
    peer.write_all(b"R").unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.write_all(&vec![7u8; TOTAL])
        .expect("the server stopped reading the batch");
    let mut echoed = vec![0u8; TOTAL];
    peer.read_exact(&mut echoed).expect("the batch came back");

    drop(peer);
    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}

/// A peer that reads again gets every byte it wrote: the held receive resumes.
#[test]
fn a_held_forward_recv_buf_resumes_when_its_peer_reads() {
    const TOTAL: usize = 32 << 20;
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(64)
        .send_pool(64, 16384)
        .send_slab_slots(8)
        .forward_hold_cap(2)
        .build()
        .expect("config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Modes>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound address");

    let mut peer = TcpStream::connect(addr).unwrap();
    peer.write_all(b"R").unwrap();
    let mut writer = peer.try_clone().unwrap();
    let writing = std::thread::spawn(move || {
        let chunk = vec![7u8; 1 << 20];
        let mut sent = 0;
        while sent < TOTAL {
            writer.write_all(&chunk).unwrap();
            sent += chunk.len();
        }
    });
    // Long enough for the peer's unread replies to fill the hold cap.
    std::thread::sleep(Duration::from_millis(200));
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut received = 0;
    while received < TOTAL {
        match peer.read(&mut buf) {
            Ok(0) => panic!("EOF after {received} of {TOTAL} bytes"),
            Ok(n) => {
                assert!(buf[..n].iter().all(|&b| b == 7), "corrupt echo");
                received += n;
            }
            Err(e) => panic!("read after {received} of {TOTAL} bytes: {e}"),
        }
    }
    writing.join().unwrap();
    drop(peer);
    shutdown.shutdown();
    for h in handles {
        let _ = h.join();
    }
}
