//! Allocations made by direct receives (plaintext connections from `connect`)
//! when every receive ends at a message boundary and `with_bytes` consumes all
//! of it. In its own test binary, for the counting global allocator.
#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// Counts allocations of at least 32 KiB, the size of a direct receive's
/// buffer and not of anything else the client loop allocates.
struct CountLarge;

static LARGE: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for CountLarge {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() >= 32 * 1024 {
            LARGE.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size >= 32 * 1024 {
            LARGE.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOC: CountLarge = CountLarge;

/// Batches, messages per batch, and message size for the current run.
static SHAPE: Mutex<(usize, usize, usize)> = Mutex::new((0, 0, 0));
/// Batches read before counting starts: the first receives allocate the
/// connection's buffer and the pool's.
const WARMUP: usize = 4;

static SERVER: Mutex<Option<SocketAddr>> = Mutex::new(None);
/// Held by each test for its whole run: the tests share `SERVER`, `SHAPE`,
/// `RESULT` and the allocation counter, and `cargo test` runs them on
/// parallel threads.
static TEST_LOCK: Mutex<()> = Mutex::new(());
static RESULT: Mutex<Option<Result<u64, String>>> = Mutex::new(None);

/// Read the batches `SHAPE` describes, each message a 4-byte length and its
/// payload, with `with_bytes` and no length hint, dropping each payload
/// before the next read, and send one byte after each batch to ask for the
/// next.
struct Client;

impl AsyncEventHandler for Client {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let addr = SERVER.lock().unwrap().unwrap();
            let (batches, frames, size) = *SHAPE.lock().unwrap();
            let r = async {
                let mut conn = ringline::connect(addr)
                    .await
                    .map_err(|e| format!("connect: {e}"))?;
                let mut start = 0;
                for batch in 0..batches {
                    if batch == WARMUP {
                        start = LARGE.load(Ordering::Relaxed);
                    }
                    for m in 0..frames {
                        let mut value = None;
                        let n = conn
                            .with_bytes(|b| {
                                if b.len() < 4 + size {
                                    return ParseResult::NeedMore;
                                }
                                value = Some(b.slice(4..4 + size));
                                ParseResult::Consumed(4 + size)
                            })
                            .await;
                        if n == 0 {
                            return Err(format!("EOF in batch {batch}, frame {m}"));
                        }
                        drop(value);
                    }
                    conn.send(b"n").map_err(|e| format!("send: {e}"))?;
                }
                Ok(LARGE.load(Ordering::Relaxed) - start)
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
        Client
    }
}

/// Run the client against a server that sends `batches` batches of
/// `frames` messages of `size` bytes, and return the allocations of 32 KiB or
/// more after the warmup.
fn run(batches: usize, frames: usize, size: usize) -> u64 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    *SERVER.lock().unwrap() = Some(listener.local_addr().unwrap());
    *SHAPE.lock().unwrap() = (batches, frames, size);
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let mut batch = Vec::new();
        for _ in 0..frames {
            batch.extend_from_slice(&(size as u32).to_be_bytes());
            batch.resize(batch.len() + size, 0x5a);
        }
        let mut ask = [0u8; 1];
        for b in 0..batches {
            s.write_all(&batch).unwrap();
            if b + 1 < batches {
                s.read_exact(&mut ask).unwrap();
            }
        }
    });
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .build()
        .expect("config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Client>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    server.join().unwrap();
    let large = RESULT
        .lock()
        .unwrap()
        .take()
        .expect("client did not finish")
        .expect("client");
    eprintln!("{batches} batches of {frames} x {size} B: {large} allocations of 32 KiB or more");
    large
}

/// Small messages fit the connection's own buffer, which a receive reuses
/// once the parser has consumed it.
#[test]
fn a_direct_receive_reuses_a_consumed_buffer() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let batches = 2_000;
    let large = run(batches, 16, 60);
    assert!(
        large * 20 <= batches as u64,
        "{large} allocations of 32 KiB or more in {batches} batches"
    );
}

/// Messages larger than the connection's own buffer, and batches of smaller
/// messages that together are larger, borrow a buffer from the pool and give
/// it back, so after the warmup no batch allocates.
#[test]
fn large_messages_reuse_pooled_buffers() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for (frames, size) in [
        (1, 64 * 1024),
        (4, 64 * 1024),
        (1, 1 << 20),
        (16, 4096),
        (16, 8192),
    ] {
        let batches = 200;
        let large = run(batches, frames, size);
        assert!(
            large * 20 <= batches as u64,
            "{frames} x {size} B: {large} allocations of 32 KiB or more in {batches} batches"
        );
    }
}
