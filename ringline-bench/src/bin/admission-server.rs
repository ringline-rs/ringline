//! Server for the contended case of Experiment B
//! (`docs/send-admission-design.md`, section 4).
//!
//! A request is 8 bytes: the reply length and a tag, each a little-endian
//! `u32`. The reply is that many bytes, starting with the tag and the length.
//! Each connection answers one request at a time: it sends the reply, waits for
//! it to settle, then reads the next request.
//!
//! - A reply of at most `--small-max` bytes is sent with the call
//!   `--small-send` names: `send_admitted`, or `send`, which takes no place in
//!   the send-capacity FIFO. A `send` the pool refuses aborts the connection.
//! - A larger reply is always sent with `send_admitted`.
//! - Every wait for admission is bounded by `--admit-limit-ms`, and every
//!   wait for settlement by `--settle-limit-ms`. A connection past either is
//!   aborted.
//!
//! One worker, so every connection shares one send pool and one FIFO. The
//! counters are printed as one JSON line on SIGINT or SIGTERM.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering::Relaxed};
use std::time::Duration;

use clap::Parser;
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SmallSend {
    Admitted,
    Send,
}

#[derive(Parser)]
#[command(
    name = "admission-server",
    about = "Experiment B's contended-case server"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7979")]
    addr: SocketAddr,
    /// How replies of at most `--small-max` bytes are sent.
    #[arg(long, value_enum)]
    small_send: SmallSend,
    #[arg(long, default_value_t = 4096)]
    small_max: u32,
    #[arg(long)]
    admit_limit_ms: u64,
    #[arg(long)]
    settle_limit_ms: u64,
    /// Send-pool slots.
    #[arg(long, default_value_t = 512)]
    pool_slots: u16,
    /// Send-pool slot size in bytes.
    #[arg(long, default_value_t = 16384)]
    slot_size: u32,
    /// Pin the worker to this CPU.
    #[arg(long, default_value_t = 0)]
    cpu: usize,
}

static SMALL_SEND: AtomicU8 = AtomicU8::new(0);
static SMALL_MAX: AtomicU64 = AtomicU64::new(0);
static ADMIT_LIMIT_MS: AtomicU64 = AtomicU64::new(0);
static SETTLE_LIMIT_MS: AtomicU64 = AtomicU64::new(0);

/// Indexed by `Kind`: small replies first, large second.
struct Counters {
    replies: [AtomicU64; 2],
    refused: [AtomicU64; 2],
    admit_timeouts: [AtomicU64; 2],
    settle_aborts: [AtomicU64; 2],
    failed: [AtomicU64; 2],
}

static COUNTERS: Counters = Counters {
    replies: [AtomicU64::new(0), AtomicU64::new(0)],
    refused: [AtomicU64::new(0), AtomicU64::new(0)],
    admit_timeouts: [AtomicU64::new(0), AtomicU64::new(0)],
    settle_aborts: [AtomicU64::new(0), AtomicU64::new(0)],
    failed: [AtomicU64::new(0), AtomicU64::new(0)],
};

const SMALL: usize = 0;
const LARGE: usize = 1;

async fn serve(conn: Connection) {
    let (mut tx, mut rx) = conn.split();
    let use_send = SMALL_SEND.load(Relaxed) == 1;
    let small_max = SMALL_MAX.load(Relaxed) as usize;
    let admit_limit = Duration::from_millis(ADMIT_LIMIT_MS.load(Relaxed));
    let settle_limit = Duration::from_millis(SETTLE_LIMIT_MS.load(Relaxed));
    let mut reply = Vec::new();
    loop {
        let mut request = None;
        let n = rx
            .with_data(|data| {
                if data.len() < 8 {
                    return ParseResult::NeedMore;
                }
                let len = u32::from_le_bytes(data[0..4].try_into().unwrap());
                let tag = u32::from_le_bytes(data[4..8].try_into().unwrap());
                request = Some((len.max(8) as usize, tag));
                ParseResult::Consumed(8)
            })
            .await;
        let Some((len, tag)) = request.filter(|_| n > 0) else {
            break;
        };
        reply.clear();
        reply.extend_from_slice(&tag.to_le_bytes());
        reply.extend_from_slice(&(len as u32).to_le_bytes());
        reply.resize(len, b'r');
        let kind = if len <= small_max { SMALL } else { LARGE };
        let sent = if kind == SMALL && use_send {
            match tx.send(&reply) {
                Ok(sent) => sent,
                Err(e) if e.kind() == std::io::ErrorKind::Other && tx.is_alive() => {
                    COUNTERS.refused[kind].fetch_add(1, Relaxed);
                    tx.abort();
                    break;
                }
                Err(_) => {
                    COUNTERS.failed[kind].fetch_add(1, Relaxed);
                    break;
                }
            }
        } else {
            match ringline::timeout(admit_limit, tx.send_admitted(&reply)).await {
                Ok(Ok(sent)) => sent,
                Ok(Err(_)) => {
                    COUNTERS.failed[kind].fetch_add(1, Relaxed);
                    break;
                }
                Err(_elapsed) => {
                    COUNTERS.admit_timeouts[kind].fetch_add(1, Relaxed);
                    tx.abort();
                    break;
                }
            }
        };
        match ringline::timeout(settle_limit, sent).await {
            Ok(Ok(_)) => {
                COUNTERS.replies[kind].fetch_add(1, Relaxed);
            }
            Ok(Err(_)) => {
                COUNTERS.failed[kind].fetch_add(1, Relaxed);
                break;
            }
            Err(_elapsed) => {
                COUNTERS.settle_aborts[kind].fetch_add(1, Relaxed);
                tx.abort();
                break;
            }
        }
    }
}

struct Handler;
impl AsyncEventHandler for Handler {
    fn on_accept(&self, conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
        serve(conn)
    }
    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

fn main() {
    let args = Args::parse();
    SMALL_SEND.store(u8::from(args.small_send == SmallSend::Send), Relaxed);
    SMALL_MAX.store(u64::from(args.small_max), Relaxed);
    ADMIT_LIMIT_MS.store(args.admit_limit_ms, Relaxed);
    SETTLE_LIMIT_MS.store(args.settle_limit_ms, Relaxed);
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(true)
        .core_offset(args.cpu)
        .max_connections(4096)
        .send_pool(args.pool_slots, args.slot_size)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind(args.addr)
        .launch::<Handler>()
        .expect("launch");
    eprintln!(
        "admission-server: ready on {} (small_send={}, admit={} ms, settle={} ms)",
        args.addr,
        if args.small_send == SmallSend::Send {
            "send"
        } else {
            "admitted"
        },
        args.admit_limit_ms,
        args.settle_limit_ms
    );
    runtime.wait_on_signal();
    for h in handles {
        h.join().ok();
    }
    let c = &COUNTERS;
    let pair = |a: &[AtomicU64; 2]| [a[SMALL].load(Relaxed), a[LARGE].load(Relaxed)];
    println!(
        "{}",
        serde_json::json!({
            "replies": pair(&c.replies),
            "refused": pair(&c.refused),
            "admit_timeouts": pair(&c.admit_timeouts),
            "settle_aborts": pair(&c.settle_aborts),
            "failed": pair(&c.failed),
        })
    );
}
