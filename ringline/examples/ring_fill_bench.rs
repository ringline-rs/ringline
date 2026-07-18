//! Recv buffer-ring throughput harness.
//!
//! Reproduces the concurrency/large-response throughput cliff and reports the
//! ring-starvation counters (parked multishot recvs, fallback one-shot recvs)
//! alongside throughput, so the mechanism is visible — not just the symptom.
//! Used to (a) de-risk provided-buffer geometry and (b) validate that the
//! adaptive-recv-buffering work flattens the cliff. See
//! `docs/recv-buffer-adaptive-design.md`.
//!
//! Protocol: the ringline client sends a 4-byte little-endian length request;
//! the in-process std-thread server echoes back exactly that many bytes. This
//! lets one connection be driven with a fixed response size or a mixed
//! small/large distribution.
//!
//! Env knobs:
//!   MSG_SIZE  response size in bytes for fixed modes (default 262144)
//!   SMALL     small size for MODE=mixed (default 8192)
//!   LARGE     large size for MODE=mixed (default 262144)
//!   CONNS     concurrent connections (default 1)
//!   SECS      run duration seconds (default 5)
//!   RING      provided-ring entry count / power of two (default 256)
//!   BUF       provided-ring buffer size bytes (default 16384)
//!   MODE      whole | bytes | mixed (default whole)
//!             whole  = with_data, parse a full response
//!             bytes  = with_bytes (zero-copy value slices; redis-shaped)
//!             mixed  = with_data, alternate SMALL/LARGE per round (index-derived)
//!   PORT      server port (default 7891)
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, ConnCtx, ParseResult, RinglineBuilder, connect};

static TOTAL_BYTES: AtomicU64 = AtomicU64::new(0);
static TOTAL_ROUNDS: AtomicU64 = AtomicU64::new(0);
static DONE_TASKS: AtomicU64 = AtomicU64::new(0);
static ELAPSED_NS: AtomicU64 = AtomicU64::new(0);

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

/// Echo server: read a 4-byte LE length, write that many bytes. Binds all
/// interfaces so it works both in-process (localhost) and cross-host.
fn server(port: u16, max_size: usize) {
    let listener = TcpListener::bind(("0.0.0.0", port)).expect("bind");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream: TcpStream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            std::thread::spawn(move || {
                stream.set_nodelay(true).ok();
                let payload = vec![0x41u8; max_size];
                let mut len_buf = [0u8; 4];
                loop {
                    if stream.read_exact(&mut len_buf).is_err() {
                        return;
                    }
                    let n = u32::from_le_bytes(len_buf) as usize;
                    if n == 0 || n > max_size {
                        return;
                    }
                    if stream.write_all(&payload[..n]).is_err() {
                        return;
                    }
                }
            });
        }
    });
}

/// Response size for round `i` in the chosen mode.
fn size_for_round(mode: &str, i: u64, msg: usize, small: usize, large: usize) -> usize {
    if mode == "mixed" {
        // Deterministic 3:1 small:large interleave (no rng in the hot path).
        if i % 4 == 3 { large } else { small }
    } else {
        msg
    }
}

struct Bench;

impl AsyncEventHandler for Bench {
    fn on_accept(&self, _c: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let port = env_u64("PORT", 7891) as u16;
        let conns = env_u64("CONNS", 1);
        let msg = env_u64("MSG_SIZE", 1 << 18) as usize;
        let small = env_u64("SMALL", 8192) as usize;
        let large = env_u64("LARGE", 1 << 18) as usize;
        let secs = env_u64("SECS", 5);
        let mode = std::env::var("MODE").unwrap_or_else(|_| "whole".into());
        Some(Box::pin(async move {
            let target_host = std::env::var("TARGET").unwrap_or_else(|_| "127.0.0.1".into());
            let target: std::net::SocketAddr =
                format!("{target_host}:{port}").parse().unwrap();
            let start = Instant::now();
            for _ in 0..conns {
                let mode = mode.clone();
                let _ = ringline::spawn(async move {
                    let conn = connect(target)
                        .expect("connect submit")
                        .await
                        .expect("connect");
                    let deadline = Instant::now() + Duration::from_secs(secs);
                    let mut bytes = 0u64;
                    let mut rounds = 0u64;
                    while Instant::now() < deadline {
                        let want = size_for_round(&mode, rounds, msg, small, large);
                        let req = (want as u32).to_le_bytes();
                        if conn.send_nowait(&req).is_err() {
                            break;
                        }
                        let got = if mode == "bytes" {
                            conn.with_bytes(move |b| {
                                if b.len() >= want {
                                    ParseResult::Consumed(want)
                                } else {
                                    ParseResult::NeedMore
                                }
                            })
                            .await
                        } else {
                            conn.with_data(move |d| {
                                if d.len() >= want {
                                    ParseResult::Consumed(want)
                                } else {
                                    ParseResult::NeedMore
                                }
                            })
                            .await
                        };
                        if got == 0 {
                            break;
                        }
                        bytes += want as u64;
                        rounds += 1;
                    }
                    TOTAL_BYTES.fetch_add(bytes, Ordering::Relaxed);
                    TOTAL_ROUNDS.fetch_add(rounds, Ordering::Relaxed);
                    if DONE_TASKS.fetch_add(1, Ordering::Relaxed) + 1 == conns {
                        ELAPSED_NS.store(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
                        ringline::request_shutdown().ok();
                    }
                });
            }
        }))
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        Bench
    }
}

fn main() {
    let port = env_u64("PORT", 7891) as u16;
    let msg = env_u64("MSG_SIZE", 1 << 18) as usize;
    let large = env_u64("LARGE", 1 << 18) as usize;
    let ring = env_u64("RING", 256) as u16;
    let buf = env_u64("BUF", 16384) as u32;
    let conns = env_u64("CONNS", 1);
    let mode = std::env::var("MODE").unwrap_or_else(|_| "whole".into());
    // ROLE=server: run only the echo server (for cross-host: server on one box).
    // ROLE=client: run only the ringline adaptive-recv client against TARGET.
    // unset: localhost — in-process server + client (default).
    let role = std::env::var("ROLE").unwrap_or_default();

    // Server must be able to serve the largest response any mode will request.
    let max_size = msg.max(large);

    if role == "server" {
        server(port, max_size);
        eprintln!("[ring_fill_bench] echo server on 0.0.0.0:{port}, max {max_size}B — Ctrl-C to stop");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    if role != "client" {
        // localhost: start the in-process echo server.
        server(port, max_size);
        std::thread::sleep(Duration::from_millis(100));
    }

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(1024)
        .recv_buffer(ring, buf)
        .max_connections((conns + 8) as u32)
        .build()
        .expect("valid config");

    let (_shutdown, handles) = RinglineBuilder::new(config)
        .launch::<Bench>()
        .expect("launch");
    for h in handles {
        let _ = h.join();
    }

    let bytes = TOTAL_BYTES.load(Ordering::Relaxed);
    let rounds = TOTAL_ROUNDS.load(Ordering::Relaxed);
    let elapsed_s = ELAPSED_NS.load(Ordering::Relaxed) as f64 / 1e9;
    let mib_s = if elapsed_s > 0.0 {
        bytes as f64 / (1 << 20) as f64 / elapsed_s
    } else {
        0.0
    };

    use ringline::metrics::{BYTES, POOL, bytes as bx, pool};
    let received = BYTES.value(bx::RECEIVED).unwrap_or(0);
    let fallback_rx = BYTES.value(bx::FALLBACK_RECEIVED).unwrap_or(0);
    let ring_empty = POOL.value(pool::BUFFER_RING_EMPTY).unwrap_or(0);
    let parked = POOL.value(pool::RECV_PARKED).unwrap_or(0);
    let fallbacks = POOL.value(pool::RECV_FALLBACK).unwrap_or(0);

    println!(
        "RESULT mode={mode} msg={msg} conns={conns} ring={ring} buf={buf} rounds={rounds} \
         MiB/s={mib_s:.1} ring_empty={ring_empty} parked={parked} fallbacks={fallbacks} \
         fallback_rx_frac={:.3} elapsed_s={elapsed_s:.2} rx_bytes={received}",
        if received > 0 {
            fallback_rx as f64 / received as f64
        } else {
            0.0
        },
    );
}
