//! Timer cost harness (#838). One pinned worker.
//!
//! MODE=timeout  PENDING tasks each hold a one-hour `sleep`; one task then
//!               loops `timeout(60 s, yield_now())` for SECS. The inner future
//!               pends once, so each op arms the timer and then drops it.
//! MODE=sleep    CONC tasks each loop `sleep(SLEEP_US)` for SECS.
//! MODE=idle     no tasks; the worker runs at TICK_US for SECS.
//! MODE=sleeplat one task loops `sleep(SLEEP_US)` for SECS and records each
//!               sleep's overshoot: the time from the call to when the task
//!               runs again, less SLEEP_US.
//!
//! Prints one RESULT line: ops, ops/s, process CPU (user + sys) per op and per
//! second, ring CQEs per op, and the median and p99 overshoot
//! (`over_med_ns`, `over_p99_ns`), which are 0 outside MODE=sleeplat.
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

static ARMED: AtomicU64 = AtomicU64::new(0);
static OPS: AtomicU64 = AtomicU64::new(0);
static START: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
static FINISHED: AtomicU64 = AtomicU64::new(0);
static OVERSHOOT_NS: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

fn env_u64(k: &str, d: u64) -> u64 {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

fn cpu_s() -> f64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 * 1e-6;
    t(ru.ru_utime) + t(ru.ru_stime)
}

fn cqes() -> u64 {
    use ringline::metrics::{RING, ring};
    RING.value(ring::CQE_PROCESSED).unwrap_or(0)
}

struct Bench;

impl AsyncEventHandler for Bench {
    fn on_accept(&self, _c: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let mode = std::env::var("MODE").unwrap_or_else(|_| "timeout".into());
        let pending = env_u64("PENDING", 0);
        let conc = env_u64("CONC", 1);
        let sleep_us = env_u64("SLEEP_US", 100);
        Some(Box::pin(async move {
            for _ in 0..pending {
                ringline::spawn(async {
                    ARMED.fetch_add(1, Ordering::Relaxed);
                    ringline::sleep(Duration::from_secs(3600)).await;
                })
                .expect("spawn pending sleeper");
            }
            match mode.as_str() {
                "timeout" => {
                    ringline::spawn(async {
                        while !START.load(Ordering::Relaxed) {
                            ringline::sleep(Duration::from_millis(1)).await;
                        }
                        let mut n = 0u64;
                        while !STOP.load(Ordering::Relaxed) {
                            let r =
                                ringline::timeout(Duration::from_secs(60), ringline::yield_now())
                                    .await;
                            assert!(r.is_ok());
                            n += 1;
                        }
                        OPS.fetch_add(n, Ordering::Relaxed);
                        FINISHED.fetch_add(1, Ordering::Relaxed);
                    })
                    .expect("spawn timeout loop");
                }
                "sleep" => {
                    for _ in 0..conc {
                        ringline::spawn(async move {
                            while !START.load(Ordering::Relaxed) {
                                ringline::sleep(Duration::from_millis(1)).await;
                            }
                            let mut n = 0u64;
                            while !STOP.load(Ordering::Relaxed) {
                                ringline::sleep(Duration::from_micros(sleep_us)).await;
                                n += 1;
                            }
                            OPS.fetch_add(n, Ordering::Relaxed);
                            FINISHED.fetch_add(1, Ordering::Relaxed);
                        })
                        .expect("spawn sleeper");
                    }
                }
                "sleeplat" => {
                    ringline::spawn(async move {
                        while !START.load(Ordering::Relaxed) {
                            ringline::sleep(Duration::from_millis(1)).await;
                        }
                        let want = Duration::from_micros(sleep_us);
                        let mut over = Vec::with_capacity(1 << 16);
                        while !STOP.load(Ordering::Relaxed) {
                            let t = Instant::now();
                            ringline::sleep(want).await;
                            over.push(t.elapsed().saturating_sub(want).as_nanos() as u64);
                        }
                        OPS.fetch_add(over.len() as u64, Ordering::Relaxed);
                        *OVERSHOOT_NS.lock().unwrap() = over;
                        FINISHED.fetch_add(1, Ordering::Relaxed);
                    })
                    .expect("spawn sleeplat");
                }
                _ => {}
            }
        }))
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        Bench
    }
}

fn main() {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "timeout".into());
    if !matches!(mode.as_str(), "timeout" | "sleep" | "idle" | "sleeplat") {
        eprintln!("unknown MODE={mode}: use timeout, sleep, sleeplat or idle");
        std::process::exit(2);
    }
    let pending = env_u64("PENDING", 0);
    let conc = env_u64("CONC", 1);
    let secs = env_u64("SECS", 5);
    let tick_us = env_u64("TICK_US", 1000);
    let sleep_us = env_u64("SLEEP_US", 100);

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(true)
        .max_connections(16)
        .standalone_task_capacity((pending + conc + 16) as u32)
        .tick_timeout_us(tick_us)
        .build()
        .expect("valid config");
    let (_runtime, _handles) = RinglineBuilder::new(config)
        .launch::<Bench>()
        .expect("launch");

    // Let every pending sleeper be polled once, so its timer is armed.
    let t0 = Instant::now();
    while ARMED.load(Ordering::Relaxed) < pending {
        assert!(t0.elapsed() < Duration::from_secs(60), "sleepers not armed");
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(500));

    let (c0, q0, w0) = (cpu_s(), cqes(), Instant::now());
    START.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_secs(secs));
    STOP.store(true, Ordering::Relaxed);
    let (c1, q1, w1) = (cpu_s(), cqes(), Instant::now());
    let want = match mode.as_str() {
        "timeout" | "sleeplat" => 1,
        "sleep" => conc,
        _ => 0,
    };
    let t1 = Instant::now();
    while FINISHED.load(Ordering::Relaxed) < want {
        assert!(t1.elapsed() < Duration::from_secs(10), "loops did not stop");
        std::thread::sleep(Duration::from_millis(1));
    }

    let wall = (w1 - w0).as_secs_f64();
    let ops = OPS.load(Ordering::Relaxed);
    let cpu = c1 - c0;
    let cq = q1 - q0;
    let per = |x: f64| if ops > 0 { x / ops as f64 } else { 0.0 };
    let mut over = std::mem::take(&mut *OVERSHOOT_NS.lock().unwrap());
    over.sort_unstable();
    let pct = |p: f64| {
        if over.is_empty() {
            0
        } else {
            over[((over.len() - 1) as f64 * p) as usize]
        }
    };
    println!(
        "RESULT mode={mode} pending={pending} conc={conc} tick_us={tick_us} sleep_us={sleep_us} \
         ops={ops} ops_s={:.0} cpu_s={cpu:.3} cpu_frac={:.4} cpu_ns_op={:.0} cqes={cq} \
         cqes_op={:.2} cqes_s={:.0} over_med_ns={} over_p99_ns={}",
        ops as f64 / wall,
        cpu / wall,
        per(cpu * 1e9),
        per(cq as f64),
        cq as f64 / wall,
        pct(0.5),
        pct(0.99),
    );
    std::process::exit(0);
}
