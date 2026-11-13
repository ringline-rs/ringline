//! The slice a `with_data` closure is given stays readable after the closure
//! passes it to `forward_recv_buf`.
//!
//! On io_uring, a forward of the whole receive buffer detaches the buffer
//! and sends it under a guard. Below `send_zc_threshold` the send copies the
//! bytes and drops the guard at once. When the buffer is a remainder that
//! `with_bytes` put back, the guard is the only handle to the allocation, so
//! the runtime holds a second one until the closure returns.
//!
//! The test reads the slice after the forward under an allocator that fills
//! freed blocks with `0xEE`. The tests are in their own binary because they
//! install a global allocator.
#![allow(clippy::manual_async_fn)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// While `POISON` is set, a freed block is filled with `0xEE` and not handed
/// back to the system allocator, so a read of freed memory reads `0xEE` and
/// touches nothing that was reused.
struct PoisonOnFree;
static POISON: AtomicBool = AtomicBool::new(false);

// SAFETY: defers to `System`; a block that is not passed on is leaked.
unsafe impl GlobalAlloc for PoisonOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if POISON.load(Ordering::Relaxed) {
            // SAFETY: the block is `layout.size()` bytes and ours until freed.
            unsafe { std::ptr::write_bytes(ptr, 0xEE, layout.size()) };
        } else {
            // SAFETY: the caller's contract.
            unsafe { System.dealloc(ptr, layout) }
        }
    }
}

#[global_allocator]
static ALLOC: PoisonOnFree = PoisonOnFree;

/// The tests share `POISON` and `OBSERVED`, and `cargo test` runs them in
/// one process.
static SERIAL: Mutex<()> = Mutex::new(());

/// What the handler's closure saw.
#[derive(Clone, Debug, PartialEq)]
struct Observed {
    /// Length of the slice the closure was given.
    len: usize,
    /// `forward_recv_buf` returned `Ok`.
    sent: bool,
    /// The slice, read after `forward_recv_buf` returned.
    after: Vec<u8>,
}
static OBSERVED: Mutex<Option<Observed>> = Mutex::new(None);

/// Waits for 100 bytes and consumes one, through `with_bytes` when
/// `FIRST_WITH_BYTES` and through `with_data` otherwise. Then echoes the
/// other 99 with `forward_recv_buf` from a `with_data` closure and reads the
/// slice again after the call.
struct SmallForward<const FIRST_WITH_BYTES: bool>;

impl<const FIRST_WITH_BYTES: bool> AsyncEventHandler for SmallForward<FIRST_WITH_BYTES> {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let (mut tx, mut rx) = conn.split();
            if FIRST_WITH_BYTES {
                rx.with_bytes(|b| {
                    if b.len() < 100 {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            } else {
                rx.with_data(|b| {
                    if b.len() < 100 {
                        ParseResult::NeedMore
                    } else {
                        ParseResult::Consumed(1)
                    }
                })
                .await;
            }
            rx.with_data(|d| {
                POISON.store(true, Ordering::SeqCst);
                let sent = tx.forward_recv_buf(d).is_ok();
                let after = d.to_vec();
                POISON.store(false, Ordering::SeqCst);
                *OBSERVED.lock().unwrap() = Some(Observed {
                    len: d.len(),
                    sent,
                    after,
                });
                ParseResult::Consumed(d.len())
            })
            .await;
            // Hold the connection until the peer closes.
            rx.with_data(|d| ParseResult::Consumed(d.len())).await;
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        SmallForward
    }
}

/// Send 100 bytes of `7` to a `SmallForward` server. Returns what its
/// closure saw and the 99 bytes echoed.
fn small_forward<H: AsyncEventHandler>() -> (Observed, Vec<u8>) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    *OBSERVED.lock().unwrap() = None;
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .send_pool(64, 16448)
        .no_fs()
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch failed");
    let addr = runtime.bound_addr().expect("bound address");

    let mut peer = TcpStream::connect(addr).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    peer.write_all(&[7u8; 100]).unwrap();
    let mut echo = vec![0u8; 99];
    let echoed = peer.read_exact(&mut echo);
    let deadline = Instant::now() + Duration::from_secs(5);
    let observed = loop {
        if let Some(observed) = OBSERVED.lock().unwrap().clone() {
            break Some(observed);
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };

    drop(peer);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    echoed.expect("the echo");
    (observed.expect("the closure did not run"), echo)
}

fn expected() -> Observed {
    Observed {
        len: 99,
        sent: true,
        after: vec![7u8; 99],
    }
}

/// Control: the receive buffer was last read through `with_data`, so the
/// accumulator's own handle keeps the allocation.
#[test]
fn a_small_forward_after_with_data_leaves_the_slice_readable() {
    let (observed, echo) = small_forward::<SmallForward<false>>();
    assert_eq!(observed, expected());
    assert_eq!(echo, vec![7u8; 99]);
}

/// The receive buffer is a remainder `with_bytes` put back.
#[test]
fn a_small_forward_after_with_bytes_leaves_the_slice_readable() {
    let (observed, echo) = small_forward::<SmallForward<true>>();
    assert_eq!(
        observed,
        expected(),
        "0xEE: the bytes were freed inside forward_recv_buf"
    );
    assert_eq!(echo, vec![7u8; 99]);
}
