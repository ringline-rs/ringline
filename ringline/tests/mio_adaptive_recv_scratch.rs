#![allow(clippy::manual_async_fn)]
//! Integration test: the mio backend's shared recv scratch buffer grows
//! adaptively toward observed message sizes instead of staying pinned at
//! the fixed 8 KiB floor.
//!
//! This is mio-only: io_uring has no equivalent shared scratch (it uses
//! per-connection kernel-managed provided buffers with size classes
//! instead — see `backend::uring::provided`). On macOS the mio backend is
//! the only one that builds, so this test runs unconditionally; on Linux
//! CI (io_uring host) it would be a no-op assertion against a gauge that's
//! never touched, so gate it to the mio backend explicitly.

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, ConnCtx, ParseResult, RinglineBuilder};

struct AsyncEcho;

impl AsyncEventHandler for AsyncEcho {
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
        AsyncEcho
    }
}

fn free_port() -> u16 {
    use std::sync::Mutex;
    static CLAIMED: Mutex<Option<std::collections::HashSet<u16>>> = Mutex::new(None);
    loop {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut guard = CLAIMED.lock().unwrap();
        if guard.get_or_insert_with(Default::default).insert(port) {
            return port;
        }
    }
}

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

fn read_exact_echo(stream: &mut TcpStream, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let mut total = 0;
    while total < len {
        match stream.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("read error: {e}"),
        }
    }
    buf.truncate(total);
    buf
}

/// A fixed 8 KiB scratch buffer would fragment a 256 KiB response into
/// ~32 read+append cycles for every single message, forever. With
/// adaptive sizing, the very first full-size message observed by the
/// parser (`ParseResult::Consumed`) pushes the worker-level `SizingPolicy`
/// target well past 64 KiB (EWMA alpha = 1/4 on an 8 KiB baseline jumps to
/// ~70 KiB in one sample), and the event loop grows the shared scratch to
/// match before the next read. This test round-trips a 256 KiB message on
/// the mio backend and asserts the scratch actually grew, observed via
/// the `ringline/recv/scratch_bytes` gauge (there is no other way to see
/// backend-private state from an integration test).
///
/// Before the Phase 5 fix, `recv_buf` was a fixed `vec![0u8; 8192]` local
/// with no policy feeding it — the gauge would never move off its initial
/// value (0, since nothing ever calls `.set()`), so this assertion is the
/// one that fails on the pre-fix code.
#[test]
fn shared_recv_scratch_grows_past_8kib_for_large_messages() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .send_pool(8, 1 << 20)
        .build()
        .expect("valid config");

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr.parse().unwrap())
        .launch::<AsyncEcho>()
        .expect("launch failed");
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();

    const MSG: usize = 256 * 1024;
    let payload: Vec<u8> = (0..MSG).map(|i| (i % 256) as u8).collect();

    // The handler echoes back whatever's in the accumulator as soon as
    // `with_data` is called, so a single 256 KiB write is observed by the
    // sizing policy as a handful of partial-chunk "messages" (whatever
    // arrived in the server's kernel recv buffer per wakeup), not one
    // 256 KiB sample — each chunk still upshifts the EWMA immediately
    // (ewma > target ⇒ upshift). Round-trip the same payload several
    // times so repeated large chunks compound the policy toward its
    // 256 KiB ceiling, rather than relying on a single sample.
    const ROUNDS: usize = 4;
    for round in 0..ROUNDS {
        stream.write_all(&payload).unwrap();
        stream.flush().unwrap();
        let echoed = read_exact_echo(&mut stream, MSG);
        assert_eq!(echoed, payload, "echo mismatch on round {round}");
    }

    // The worker has now processed several 256 KiB messages, so its
    // SizingPolicy target is well past 64 KiB and the shared scratch is
    // resized to match at the top of each event-loop iteration. Poll the
    // gauge with a generous deadline: under full-suite parallel load the
    // worker is CPU-starved and ratchets its target up over more wakeups, so
    // a tight deadline flakes. Break as soon as it crosses (normal runs finish
    // in well under a second); nudge the worker with a 1-byte keepalive echo
    // each iteration so it keeps ticking (and resizing) even when otherwise
    // idle. Only sustained starvation past the cap can fail this.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut observed = ringline::metrics::RECV_SCRATCH_BYTES.value();
    while observed < 65536 && Instant::now() < deadline {
        let _ = stream.write_all(b"x");
        let _ = stream.flush();
        let mut tmp = [0u8; 1];
        let _ = stream.read(&mut tmp);
        std::thread::sleep(Duration::from_millis(20));
        observed = ringline::metrics::RECV_SCRATCH_BYTES.value();
    }
    assert!(
        observed >= 65536,
        "shared recv scratch never grew past 8 KiB floor after {ROUNDS} large messages \
         (observed {observed} bytes) — adaptive sizing is not wired up"
    );

    drop(stream);
    shutdown.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
