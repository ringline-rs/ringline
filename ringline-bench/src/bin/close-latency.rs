//! Server-initiated close latency: how long a client waits for EOF after the
//! server has answered and closed, optionally while the server's workers keep
//! their bounded io-wq pools busy with `fsync`.
//!
//! On io_uring every connection close runs a `shutdown` on the worker's
//! bounded io-wq pool (#581), and that pool also runs regular-file I/O that
//! would block, such as `fsync`. With the pool capped
//! (`ConfigBuilder::iowq_max_workers`, #584) and every thread busy with an
//! `fsync`, a close's shutdown waits for a free thread, and the client waits
//! for its EOF. This measures that wait.
//!
//! Server: each connection's task reads one request, echoes it and returns,
//! which closes the connection. With `--fsync-tasks N`, each worker also runs
//! N tasks that loop `write_from` + `fsync` on their own file, and the server
//! prints the total `fsync` count once a second (`fsyncs=<n>`).
//!
//! Client: blocking threads connect, send, read the echo, then time the read
//! that returns EOF. The result is JSON: conns/sec and EOF-wait percentiles.
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

#[derive(Parser)]
#[command(about = "Server-initiated close latency, optionally under fsync load")]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Server {
        #[arg(long)]
        addr: SocketAddr,
        #[arg(long, default_value_t = 1)]
        workers: usize,
        /// `ConfigBuilder::iowq_max_workers`; omitted, ringline's default.
        #[arg(long)]
        iowq_max_workers: Option<u32>,
        /// `write_from` + `fsync` loops per worker.
        #[arg(long, default_value_t = 0)]
        fsync_tasks: usize,
        /// Directory for the fsync tasks' files.
        #[arg(long, default_value = "/tmp")]
        fsync_dir: std::path::PathBuf,
    },
    Client {
        #[arg(long)]
        addr: SocketAddr,
        #[arg(long, default_value_t = 16)]
        threads: usize,
        #[arg(long, default_value_t = 5)]
        warmup: u64,
        #[arg(long, default_value_t = 20)]
        duration: u64,
        #[arg(long, default_value_t = 64)]
        msg_size: usize,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

static FSYNCS: AtomicU64 = AtomicU64::new(0);
static FSYNC_TASKS: AtomicU64 = AtomicU64::new(0);
static FSYNC_DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
static WORKER: AtomicU64 = AtomicU64::new(0);

/// One `write_from` + `fsync` loop on its own file, until the runtime stops.
async fn fsync_loop(path: std::path::PathBuf) {
    let file = match ringline::fs::create(&path) {
        Ok(open) => match open.await {
            Ok(file) => file,
            Err(e) => return eprintln!("close-latency: create {}: {e}", path.display()),
        },
        Err(e) => return eprintln!("close-latency: create {}: {e}", path.display()),
    };
    let mut buf = bytes::BytesMut::zeroed(4096);
    loop {
        let (written, back) = ringline::fs::write_from(file, 0, buf).await;
        buf = back;
        if let Err(e) = written {
            return eprintln!("close-latency: write: {e}");
        }
        match ringline::fs::fsync(file) {
            Ok(sync) => {
                if let Err(e) = sync.await {
                    return eprintln!("close-latency: fsync: {e}");
                }
            }
            Err(e) => return eprintln!("close-latency: fsync: {e}"),
        }
        FSYNCS.fetch_add(1, Ordering::Relaxed);
    }
}

struct EchoOnceThenClose;

impl AsyncEventHandler for EchoOnceThenClose {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let tasks = FSYNC_TASKS.load(Ordering::Relaxed);
        if tasks == 0 {
            return None;
        }
        let worker = WORKER.fetch_add(1, Ordering::Relaxed);
        let dir = FSYNC_DIR.get().expect("fsync dir set").clone();
        Some(Box::pin(async move {
            for i in 0..tasks {
                let path = dir.join(format!("close-latency-{}-{worker}-{i}", std::process::id()));
                ringline::spawn(fsync_loop(path)).expect("spawn fsync task");
            }
        }))
    }

    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut request = Vec::new();
            let n = conn
                .with_data(|data| {
                    request.extend_from_slice(data);
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n > 0 {
                let _ = conn.send_nowait(&request);
            }
            // Returning closes the connection once the echo has been sent.
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        EchoOnceThenClose
    }
}

fn run_server(
    addr: SocketAddr,
    workers: usize,
    iowq_max_workers: Option<u32>,
    fsync_tasks: usize,
    fsync_dir: std::path::PathBuf,
) {
    FSYNC_TASKS.store(fsync_tasks as u64, Ordering::Relaxed);
    let _ = FSYNC_DIR.set(fsync_dir);
    let builder = ConfigBuilder::new()
        .workers(workers)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(16384)
        .send_pool(512, 4096);
    let builder = match iowq_max_workers {
        Some(n) => builder.iowq_max_workers(n),
        None => builder,
    };
    let config = builder.build().expect("valid config");
    let (_runtime, handles) = RinglineBuilder::new(config)
        .bind(addr)
        .launch::<EchoOnceThenClose>()
        .expect("launch");
    eprintln!(
        "close-latency: listening on {addr}, {workers} workers, iowq_max_workers={iowq_max_workers:?}, fsync_tasks={fsync_tasks}"
    );
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            println!("fsyncs={}", FSYNCS.load(Ordering::Relaxed));
        }
    });
    for h in handles {
        let _ = h.join();
    }
}

fn run_client(
    addr: SocketAddr,
    threads: usize,
    warmup: u64,
    duration: u64,
    msg_size: usize,
    out: Option<std::path::PathBuf>,
) {
    let measuring = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(AtomicU64::new(0));
    let payload = vec![b'x'; msg_size];
    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let (measuring, stop, errors) = (measuring.clone(), stop.clone(), errors.clone());
        let payload = payload.clone();
        handles.push(std::thread::spawn(move || {
            // EOF waits in nanoseconds, measured window only.
            let mut waits: Vec<u64> = Vec::new();
            let mut buf = vec![0u8; payload.len()];
            while !stop.load(Ordering::Relaxed) {
                let mut sock = match TcpStream::connect(addr) {
                    Ok(s) => s,
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
                if sock.write_all(&payload).is_err() || sock.read_exact(&mut buf).is_err() {
                    errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let echoed = Instant::now();
                match sock.read(&mut buf) {
                    Ok(0) => {
                        if measuring.load(Ordering::Relaxed) {
                            waits.push(echoed.elapsed().as_nanos() as u64);
                        }
                    }
                    _ => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            waits
        }));
    }
    std::thread::sleep(Duration::from_secs(warmup));
    measuring.store(true, Ordering::Relaxed);
    let started = Instant::now();
    std::thread::sleep(Duration::from_secs(duration));
    measuring.store(false, Ordering::Relaxed);
    let elapsed = started.elapsed().as_secs_f64();
    stop.store(true, Ordering::Relaxed);
    let mut waits: Vec<u64> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("client thread"))
        .collect();
    waits.sort_unstable();
    let pct = |p: f64| -> f64 {
        if waits.is_empty() {
            return 0.0;
        }
        let i = ((waits.len() as f64 * p).ceil() as usize).clamp(1, waits.len()) - 1;
        waits[i] as f64 / 1000.0
    };
    let json = format!(
        r#"{{
  "addr": "{addr}",
  "threads": {threads},
  "duration_secs": {elapsed:.3},
  "conns_per_sec": {:.2},
  "completed": {},
  "errors": {},
  "eof_wait_us_p50": {:.1},
  "eof_wait_us_p99": {:.1},
  "eof_wait_us_p999": {:.1},
  "eof_wait_us_max": {:.1}
}}"#,
        waits.len() as f64 / elapsed,
        waits.len(),
        errors.load(Ordering::Relaxed),
        pct(0.50),
        pct(0.99),
        pct(0.999),
        waits.last().copied().unwrap_or(0) as f64 / 1000.0,
    );
    match out {
        Some(path) => std::fs::write(path, &json).expect("write result"),
        None => println!("{json}"),
    }
}

fn main() {
    match Args::parse().mode {
        Mode::Server {
            addr,
            workers,
            iowq_max_workers,
            fsync_tasks,
            fsync_dir,
        } => run_server(addr, workers, iowq_max_workers, fsync_tasks, fsync_dir),
        Mode::Client {
            addr,
            threads,
            warmup,
            duration,
            msg_size,
            out,
        } => run_client(addr, threads, warmup, duration, msg_size, out),
    }
}
