//! Load for the contended case of Experiment B
//! (`docs/send-admission-design.md`, section 4), against `admission-server`.
//!
//! Every `--episode-ms`:
//! - `--stall-peers` connections each ask for a `--stall-size` reply and
//!   never read, so the replies hold send-pool slots until the server aborts
//!   them (`--settle-limit-ms` on the server);
//! - `--large-delay-ms` later, one connection asks for a `--large-size` reply,
//!   which needs more slots than are free and waits at the head of the
//!   server's send-capacity FIFO, then reads it.
//!
//! Throughout, `--small-conns` connections offer `--small-size` requests at
//! `--small-rate` per second in total, open loop. Each small reply's latency
//! is measured from its scheduled send time, so a reply delayed behind the
//! head is charged for the whole delay. A small request whose connection
//! ends before its reply arrives is lost, and the connection is reopened.
//!
//! Prints one JSON object: the small replies offered after `--warmup` (sent
//! before the drain), delivered within `--within-ms`, delivered late and
//! lost, their latency percentiles, and each episode's large-reply outcome.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;

#[derive(Parser, Clone)]
#[command(name = "admission-load", about = "Experiment B's contended-case load")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7979")]
    addr: SocketAddr,
    /// Seconds of load after the warmup.
    #[arg(long, default_value_t = 60)]
    duration: u64,
    /// Seconds before measuring.
    #[arg(long, default_value_t = 4)]
    warmup: u64,
    #[arg(long, default_value_t = 16)]
    small_conns: usize,
    /// Small requests per second, over all small connections.
    #[arg(long, default_value_t = 2000)]
    small_rate: u64,
    #[arg(long, default_value_t = 256)]
    small_size: u32,
    /// A small reply counts as delivered within the limit when its latency is
    /// at most this. Experiment B sets it to the server's `--admit-limit-ms`.
    #[arg(long)]
    within_ms: u64,
    #[arg(long, default_value_t = 4000)]
    episode_ms: u64,
    #[arg(long, default_value_t = 3)]
    stall_peers: usize,
    #[arg(long, default_value_t = 2 << 20)]
    stall_size: u32,
    /// `SO_RCVBUF` on the stalled peers' sockets, so the kernel takes less of
    /// their replies and more stays in the send pool.
    #[arg(long, default_value_t = 4096)]
    stall_rcvbuf: i32,
    #[arg(long, default_value_t = 7 << 20)]
    large_size: u32,
    #[arg(long, default_value_t = 200)]
    large_delay_ms: u64,
}

fn request(len: u32, tag: u32) -> [u8; 8] {
    let mut r = [0u8; 8];
    r[0..4].copy_from_slice(&len.to_le_bytes());
    r[4..8].copy_from_slice(&tag.to_le_bytes());
    r
}

fn connect(addr: SocketAddr) -> TcpStream {
    loop {
        match TcpStream::connect(addr) {
            Ok(s) => {
                s.set_nodelay(true).ok();
                return s;
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

/// One small connection's results. `latencies` holds the delivered replies'
/// latencies in nanoseconds, for requests scheduled inside the window.
#[derive(Default)]
struct Small {
    offered: u64,
    lost: u64,
    latencies: Vec<u64>,
    reconnects: u64,
}

/// Offer one connection's share of the small requests, open loop, until
/// `stop`, then wait up to `drain` for the replies still due.
fn small_conn(args: &Args, index: usize, start: Instant, window: (Instant, Instant)) -> Small {
    let mut out = Small::default();
    let interval = Duration::from_nanos(1_000_000_000 * args.small_conns as u64 / args.small_rate);
    let mut next = start + interval * index as u32 / args.small_conns as u32;
    let stop = window.1;
    let drain = stop + Duration::from_millis(args.within_ms) + Duration::from_secs(2);
    let size = args.small_size as usize;
    let mut conn = connect(args.addr);
    let mut pending: std::collections::VecDeque<(u32, Instant)> = Default::default();
    let mut buf = vec![0u8; size * 64];
    let mut filled = 0usize;
    let mut tag = 0u32;
    let in_window = |t: Instant| t >= window.0 && t < window.1;
    loop {
        let now = Instant::now();
        if now >= drain || (now >= stop && pending.is_empty()) {
            break;
        }
        let mut broken = false;
        while next <= now && next < stop {
            if conn.write_all(&request(args.small_size, tag)).is_err() {
                broken = true;
                break;
            }
            if in_window(next) {
                out.offered += 1;
            }
            pending.push_back((tag, next));
            tag = tag.wrapping_add(1);
            next += interval;
        }
        if !broken {
            let wait = if next < stop {
                next.saturating_duration_since(Instant::now())
            } else {
                drain.saturating_duration_since(Instant::now())
            };
            conn.set_read_timeout(Some(wait.max(Duration::from_micros(100))))
                .ok();
            match conn.read(&mut buf[filled..]) {
                Ok(0) => broken = true,
                Ok(n) => {
                    filled += n;
                    let at = Instant::now();
                    let mut used = 0;
                    while filled - used >= size {
                        let got = u32::from_le_bytes(buf[used..used + 4].try_into().unwrap());
                        let (want, scheduled) =
                            pending.pop_front().expect("a reply with no request");
                        assert_eq!(got, want, "small replies out of order");
                        if in_window(scheduled) {
                            out.latencies.push((at - scheduled).as_nanos() as u64);
                        }
                        used += size;
                    }
                    buf.copy_within(used..filled, 0);
                    filled -= used;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
                Err(_) => broken = true,
            }
        }
        if broken {
            out.lost += pending.iter().filter(|(_, t)| in_window(*t)).count() as u64;
            pending.clear();
            filled = 0;
            out.reconnects += 1;
            conn = connect(args.addr);
        }
    }
    out.lost += pending.iter().filter(|(_, t)| in_window(*t)).count() as u64;
    out
}

/// One episode's stalled peers and large reply. Returns the large reply's
/// time from request to its last byte, or `None` if its connection ended
/// first. The stalled peers stay open until 100 ms before the episode ends,
/// so the server, not this client, ends them.
fn episode(args: &Args, at: Instant) -> Option<Duration> {
    thread::sleep(at.saturating_duration_since(Instant::now()));
    let hold_until = at + Duration::from_millis(args.episode_ms.saturating_sub(100));
    let mut stalled = Vec::new();
    for i in 0..args.stall_peers {
        let mut s = connect(args.addr);
        let fd = s.as_raw_fd();
        let size = args.stall_rcvbuf;
        // SAFETY: `fd` is a live socket owned by `s`, and `size` outlives the call.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&size as *const i32).cast(),
                std::mem::size_of::<i32>() as libc::socklen_t,
            );
        }
        s.write_all(&request(args.stall_size, i as u32)).ok();
        stalled.push(s);
    }
    thread::sleep(Duration::from_millis(args.large_delay_ms));
    let mut large = connect(args.addr);
    large
        .set_read_timeout(Some(Duration::from_millis(args.episode_ms)))
        .ok();
    let began = Instant::now();
    let took = large
        .write_all(&request(args.large_size, u32::MAX))
        .ok()
        .and_then(|()| {
            let mut left = args.large_size as usize;
            let mut buf = vec![0u8; 1 << 20];
            while left > 0 {
                match large.read(&mut buf) {
                    Ok(0) | Err(_) => return None,
                    Ok(n) => left = left.saturating_sub(n),
                }
            }
            Some(began.elapsed())
        });
    thread::sleep(hold_until.saturating_duration_since(Instant::now()));
    drop(stalled);
    took
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[i]
}

fn main() {
    let args = Args::parse();
    let start = Instant::now() + Duration::from_millis(200);
    let window = (
        start + Duration::from_secs(args.warmup),
        start + Duration::from_secs(args.warmup + args.duration),
    );

    let larges = Arc::new(Mutex::new(Vec::new()));
    let episodes = {
        let args = args.clone();
        let larges = Arc::clone(&larges);
        thread::spawn(move || {
            let mut at = window.0;
            while at + Duration::from_millis(args.episode_ms) <= window.1 {
                let took = episode(&args, at);
                larges
                    .lock()
                    .unwrap()
                    .push(took.map(|d| d.as_millis() as u64));
                at += Duration::from_millis(args.episode_ms);
            }
        })
    };
    let smalls: Vec<_> = (0..args.small_conns)
        .map(|i| {
            let args = args.clone();
            thread::spawn(move || small_conn(&args, i, start, window))
        })
        .collect();
    let smalls: Vec<Small> = smalls.into_iter().map(|h| h.join().unwrap()).collect();
    episodes.join().unwrap();

    let offered: u64 = smalls.iter().map(|s| s.offered).sum();
    let lost: u64 = smalls.iter().map(|s| s.lost).sum();
    let reconnects: u64 = smalls.iter().map(|s| s.reconnects).sum();
    let mut lat: Vec<u64> = smalls
        .iter()
        .flat_map(|s| s.latencies.iter().copied())
        .collect();
    lat.sort_unstable();
    let within_ns = args.within_ms * 1_000_000;
    let within = lat.iter().filter(|&&l| l <= within_ns).count() as u64;
    let late = lat.len() as u64 - within;
    let larges = larges.lock().unwrap().clone();
    println!(
        "{}",
        serde_json::json!({
            "offered": offered,
            "delivered_within": within,
            "delivered_late": late,
            "lost": lost,
            "not_within": offered - within,
            "reconnects": reconnects,
            "within_ms": args.within_ms,
            "p50_ns": percentile(&lat, 0.50),
            "p99_ns": percentile(&lat, 0.99),
            "p999_ns": percentile(&lat, 0.999),
            "max_ns": lat.last().copied().unwrap_or(0),
            "episodes": larges.len(),
            "large_ms": larges,
        })
    );
}
