//! Recv throughput harness.
//!
//! On io_uring the client's connection is a plaintext outbound connection,
//! which receives directly into its accumulator (`docs/recv-direct-design.md`).
//! On mio every MODE measures the mio read path.
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
//!   MODE      whole | bytes | mixed (default whole)
//!             whole    = with_data, parse a full response (1 accumulator copy)
//!             bytes    = with_bytes (zero-copy value slices; redis-shaped)
//!             mixed    = with_data, alternate SMALL/LARGE per round (index-derived)
//!   PORT      server port (default 7891)
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, connect,
};

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
    fn on_accept(&self, _c: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let port = env_u64("PORT", 7891) as u16;
        let conns = env_u64("CONNS", 1);
        // on_start runs per worker, spawning `conns` tasks each → workers*conns
        // total connections. The shutdown trigger fires on the last of them.
        let workers = env_u64("WORKERS", 1);
        let msg = env_u64("MSG_SIZE", 1 << 18) as usize;
        let small = env_u64("SMALL", 8192) as usize;
        let large = env_u64("LARGE", 1 << 18) as usize;
        let secs = env_u64("SECS", 5);
        let mode = std::env::var("MODE").unwrap_or_else(|_| "whole".into());
        Some(Box::pin(async move {
            let target_host = std::env::var("TARGET").unwrap_or_else(|_| "127.0.0.1".into());
            let target: std::net::SocketAddr = format!("{target_host}:{port}").parse().unwrap();
            let start = Instant::now();
            for _ in 0..conns {
                let mode = mode.clone();
                let _ = ringline::spawn(async move {
                    let conn = connect(target).await.expect("connect");
                    // Reading an outbound connection goes through its read half.
                    let (mut conn_tx, mut conn_rx) = conn.split();
                    let deadline = Instant::now() + Duration::from_secs(secs);
                    let mut bytes = 0u64;
                    let mut rounds = 0u64;
                    while Instant::now() < deadline {
                        let want = size_for_round(&mode, rounds, msg, small, large);
                        let req = (want as u32).to_le_bytes();
                        if conn_tx.send(&req).is_err() {
                            break;
                        }
                        let got = match mode.as_str() {
                            "bytes" => {
                                conn_rx
                                    .with_bytes(move |b| {
                                        if b.len() >= want {
                                            ParseResult::Consumed(want)
                                        } else {
                                            ParseResult::NeedMore
                                        }
                                    })
                                    .await
                            }
                            _ => {
                                conn_rx
                                    .with_data(move |d| {
                                        if d.len() >= want {
                                            ParseResult::Consumed(want)
                                        } else {
                                            ParseResult::NeedMore
                                        }
                                    })
                                    .await
                            }
                        };
                        if got == 0 {
                            break;
                        }
                        bytes += want as u64;
                        rounds += 1;
                    }
                    TOTAL_BYTES.fetch_add(bytes, Ordering::Relaxed);
                    TOTAL_ROUNDS.fetch_add(rounds, Ordering::Relaxed);
                    if DONE_TASKS.fetch_add(1, Ordering::Relaxed) + 1 == conns * workers {
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
    let conns = env_u64("CONNS", 1);
    let workers = env_u64("WORKERS", 1) as usize;
    let secs = env_u64("SECS", 5);
    let mode = std::env::var("MODE").unwrap_or_else(|_| "whole".into());
    if !matches!(mode.as_str(), "whole" | "bytes" | "mixed") {
        eprintln!("[ring_fill_bench] unknown MODE={mode}: use whole, bytes or mixed");
        std::process::exit(2);
    }
    // ROLE=server: run only the echo server (for cross-host: server on one box).
    // ROLE=client: run only the ringline adaptive-recv client against TARGET.
    // unset: localhost — in-process server + client (default).
    let role = std::env::var("ROLE").unwrap_or_default();

    // Server must be able to serve the largest response any mode will request.
    let max_size = msg.max(large);

    if role == "server" {
        server(port, max_size);
        eprintln!(
            "[ring_fill_bench] echo server on 0.0.0.0:{port}, max {max_size}B — Ctrl-C to stop"
        );
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
        .workers(workers)
        .pin_to_core(true)
        .sq_entries(1024)
        .max_connections((conns + 8) as u32)
        .build()
        .expect("valid config");

    let (_runtime, _handles) = RinglineBuilder::new(config)
        .launch::<Bench>()
        .expect("launch");
    // Time-based measurement: let the workers' tasks run for `secs`, then read
    // the aggregate atomics. Robust regardless of worker count (the per-task
    // shutdown trigger is unreliable across multiple workers).
    std::thread::sleep(Duration::from_secs(secs + 1));

    let bytes = TOTAL_BYTES.load(Ordering::Relaxed);
    let rounds = TOTAL_ROUNDS.load(Ordering::Relaxed);
    let elapsed_s = secs as f64;
    let mib_s = bytes as f64 / (1 << 20) as f64 / elapsed_s;

    use ringline::metrics::{BYTES, bytes as bx};
    let received = BYTES.value(bx::RECEIVED).unwrap_or(0);

    println!(
        "RESULT mode={mode} workers={workers} msg={msg} conns={conns} rounds={rounds} \
         MiB/s={mib_s:.1} elapsed_s={elapsed_s:.2} rx_bytes={received}",
    );
    // Workers are still running; exit rather than join.
    std::process::exit(0);
}
