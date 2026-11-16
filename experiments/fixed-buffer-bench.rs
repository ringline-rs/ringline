#![allow(clippy::manual_async_fn)]
//! Reads 4 KiB blocks at random offsets from PATH through ringline::direct_io
//! for SECS seconds, QD reads in flight, into slots of one registered region.
//! MODE `fixed` names the region in each buffer (READ_FIXED); `plain` uses the
//! same memory with RegionId::UNREGISTERED (READ). Prints one BENCH line with
//! the operations, the wall time and the process CPU time over the run.
//! Usage: fixed_buffer_bench PATH SECS QD MODE
use std::cell::Cell;
use std::future::Future;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ringline::buf::{IoBuf, IoBufAligned, IoBufMut};
use ringline::direct_io::DirectIoConfig;
use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, MemoryRegion, RegionId, RinglineBuilder,
};

static REGION: OnceLock<(usize, RegionId)> = OnceLock::new();
static OUTCOME: OnceLock<Result<String, String>> = OnceLock::new();

struct Slot {
    ptr: *mut u8,
    init: usize,
    region: RegionId,
}

// Safety: each slot is a disjoint 4096-byte range of leaked, 4096-aligned
// memory that outlives the runtime; one task owns each slot.
unsafe impl IoBuf for Slot {
    fn stable_ptr(&self) -> *const u8 {
        self.ptr
    }
    fn bytes_init(&self) -> usize {
        self.init
    }
    fn region(&self) -> RegionId {
        self.region
    }
}
unsafe impl IoBufMut for Slot {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }
    fn bytes_total(&self) -> usize {
        4096
    }
    unsafe fn set_init(&mut self, pos: usize) {
        self.init = self.init.max(pos);
    }
}
// Safety: every slot starts at a multiple of 4096 (see above).
unsafe impl IoBufAligned for Slot {}

fn cpu_time() -> Duration {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let t = |tv: libc::timeval| Duration::new(tv.tv_sec as u64, tv.tv_usec as u32 * 1000);
    t(ru.ru_utime) + t(ru.ru_stime)
}

async fn run(path: String, secs: u64, qd: usize, fixed: bool) -> Result<String, String> {
    let (base, id) = loop {
        if let Some(&r) = REGION.get() {
            break r;
        }
        ringline::sleep(Duration::from_millis(5)).await;
    };
    let region = if fixed { id } else { RegionId::UNREGISTERED };
    let file = ringline::direct_io::open(&path)
        .map_err(|e| format!("open submit: {e}"))?
        .await
        .map_err(|e| format!("open: {e}"))?;
    let blocks = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) / 4096;
    let blocks = if blocks == 0 { 1 << 18 } else { blocks };
    let ops = Rc::new(Cell::new(0u64));
    let failed = Rc::new(Cell::new(None::<String>));
    let start = Instant::now();
    let cpu0 = cpu_time();
    let deadline = start + Duration::from_secs(secs);
    let done = Rc::new(Cell::new(0usize));
    for i in 0..qd {
        let (ops, failed, done) = (ops.clone(), failed.clone(), done.clone());
        let ptr = (base + i * 4096) as *mut u8;
        ringline::spawn(async move {
            let mut slot = Slot {
                ptr,
                init: 0,
                region,
            };
            let mut x = 0x9e37_79b9_7f4a_7c15u64 ^ (i as u64 + 1);
            while Instant::now() < deadline {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                slot.init = 0;
                let (n, back) =
                    ringline::direct_io::read_into(file, (x % blocks) * 4096, slot).await;
                slot = back;
                match n {
                    Ok(4096) => ops.set(ops.get() + 1),
                    other => {
                        failed.set(Some(format!("read: {other:?}")));
                        break;
                    }
                }
            }
            done.set(done.get() + 1);
        })
        .map_err(|e| format!("spawn: {e}"))?;
    }
    while done.get() < qd {
        ringline::sleep(Duration::from_millis(1)).await;
    }
    let wall = start.elapsed();
    let cpu = cpu_time() - cpu0;
    let _ = ringline::direct_io::close(file);
    if let Some(e) = failed.take() {
        return Err(e);
    }
    let n = ops.get();
    Ok(format!(
        "BENCH mode={} qd={qd} ops={n} wall_s={:.3} cpu_s={:.3} ops_per_s={:.0} cpu_us_per_op={:.3}",
        if fixed { "fixed" } else { "plain" },
        wall.as_secs_f64(),
        cpu.as_secs_f64(),
        n as f64 / wall.as_secs_f64(),
        cpu.as_secs_f64() * 1e6 / n.max(1) as f64
    ))
}

struct Bench;

impl AsyncEventHandler for Bench {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let a: Vec<String> = std::env::args().collect();
            let r = run(
                a[1].clone(),
                a[2].parse().unwrap(),
                a[3].parse().unwrap(),
                a[4] == "fixed",
            )
            .await;
            let _ = OUTCOME.set(r);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        Bench
    }
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let qd: usize = a[3].parse().unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .direct_io(
            DirectIoConfig::default()
                .max_files(2)
                .max_commands_in_flight(qd as u16 + 8),
        )
        .max_registered_regions(4)
        .build()
        .expect("config");
    let (rt, handles) = RinglineBuilder::new(config)
        .launch::<Bench>()
        .expect("launch");
    let backing: &'static mut ringline::buf::AlignedBuf =
        Box::leak(Box::new(ringline::buf::AlignedBuf::zeroed(qd * 4096, 4096)));
    let base = backing.as_mut_ptr();
    // Safety: leaked, so valid and unmoved for the life of the process.
    let region = unsafe { MemoryRegion::new(base, qd * 4096) };
    let id = rt.register_region(region).expect("register_region");
    REGION.set((base as usize, id)).unwrap();
    for h in handles {
        let _ = h.join();
    }
    drop(rt);
    match OUTCOME.get() {
        Some(Ok(line)) => println!("{line}"),
        Some(Err(e)) => {
            eprintln!("bench failed: {e}");
            std::process::exit(1)
        }
        None => {
            eprintln!("bench did not finish");
            std::process::exit(1)
        }
    }
}
