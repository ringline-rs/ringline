//! A disk buffer that names a registered region (`IoBuf::region`) reads and
//! writes through the public `fs` API, and one whose memory is outside the
//! region it names is refused with `InvalidInput` and returned (#841). The
//! opcode each submission uses is checked by the lib test
//! `a_buffer_in_a_registered_region_uses_the_fixed_opcodes`.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ringline::buf::{IoBuf, IoBufMut};
use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, MemoryRegion, RegionId, RinglineBuilder,
};

const REGION_LEN: usize = 16384;

/// The leaked memory the test registers, and the id the runtime gave it.
static REGION: OnceLock<(usize, RegionId)> = OnceLock::new();
static RESULT: OnceLock<Result<(), String>> = OnceLock::new();

/// `cap` bytes of capacity at `ptr`, which may or may not be inside
/// `region`; `init` of them initialized.
struct RegionSlice {
    ptr: *mut u8,
    cap: usize,
    init: usize,
    region: RegionId,
}

// Safety: `ptr..ptr + cap` is leaked memory that outlives the runtime, the
// pointer does not change, and nothing else writes it while ringline holds
// the slice.
unsafe impl IoBuf for RegionSlice {
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

unsafe impl IoBufMut for RegionSlice {
    fn stable_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }
    fn bytes_total(&self) -> usize {
        self.cap
    }
    unsafe fn set_init(&mut self, pos: usize) {
        self.init = self.init.max(pos);
    }
}

fn file_path() -> std::path::PathBuf {
    std::env::current_dir()
        .unwrap()
        .join(format!(".krio_fixed_buffers_{}", std::process::id()))
}

async fn round_trip() -> Result<(), String> {
    // The main thread registers the region after launch.
    let deadline = Instant::now() + Duration::from_secs(10);
    let (base, id) = loop {
        if let Some(&r) = REGION.get() {
            break r;
        }
        if Instant::now() > deadline {
            return Err("the region was not registered".into());
        }
        ringline::sleep(Duration::from_millis(5)).await;
    };
    let base = base as *mut u8;
    let file = ringline::fs::open(file_path(), ringline::fs::OpenFlags::READ_WRITE, 0)
        .map_err(|e| format!("open submit: {e}"))?
        .await
        .map_err(|e| format!("open: {e}"))?;

    // Safety: `base..base + REGION_LEN` is the leaked region.
    unsafe { std::ptr::write_bytes(base, 0x6b, 4096) };
    let src = RegionSlice {
        ptr: base,
        cap: 4096,
        init: 4096,
        region: id,
    };
    let (n, _) = ringline::fs::write_from(file, 0, src).await;
    if n.map_err(|e| format!("write from the region: {e}"))? != 4096 {
        return Err("short write from the region".into());
    }
    let dst = RegionSlice {
        ptr: unsafe { base.add(4096) },
        cap: 4096,
        init: 0,
        region: id,
    };
    let (n, dst) = ringline::fs::read_into(file, 0, dst).await;
    if n.map_err(|e| format!("read into the region: {e}"))? != 4096 || dst.init != 4096 {
        return Err("short read into the region".into());
    }
    let back = unsafe { std::slice::from_raw_parts(dst.ptr, 4096) };
    if !back.iter().all(|&b| b == 0x6b) {
        return Err("the read did not return the write".into());
    }

    // Memory outside the region it names: refused at submission and handed
    // back.
    let outside: &'static mut [u8] = Box::leak(vec![0u8; 4096].into_boxed_slice());
    let wrong = RegionSlice {
        ptr: outside.as_mut_ptr(),
        cap: 4096,
        init: 4096,
        region: id,
    };
    let (n, wrong) = ringline::fs::write_from(file, 0, wrong).await;
    match n {
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {}
        other => return Err(format!("a buffer outside its region: {other:?}")),
    }
    if wrong.ptr != outside.as_mut_ptr() {
        return Err("the refused buffer came back changed".into());
    }
    ringline::fs::close(file).map_err(|e| format!("close: {e}"))
}

struct Handler;

impl AsyncEventHandler for Handler {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let _ = RESULT.set(round_trip().await);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

#[test]
fn a_buffer_in_a_registered_region_reads_and_writes_through_fs() {
    let path = file_path();
    std::fs::write(&path, [0u8; 8192]).unwrap();
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(8)
        .send_pool(8, 16384)
        .max_registered_regions(4)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<Handler>()
        .expect("launch failed");
    let backing: &'static mut [u8] = Box::leak(vec![0u8; REGION_LEN].into_boxed_slice());
    // Safety: leaked, so valid and unmoved for the life of the process.
    let region = unsafe { MemoryRegion::new(backing.as_mut_ptr(), REGION_LEN) };
    // As `region_registry.rs`: retry a transient ENOMEM or EFAULT (#589, #656).
    let deadline = Instant::now() + Duration::from_secs(5);
    let id = loop {
        match runtime.register_region(region.clone()) {
            Ok(id) => break id,
            Err(e) => {
                let msg = e.to_string();
                let transient = msg.contains("(ENOMEM)") || msg.contains("(EFAULT)");
                assert!(
                    transient && Instant::now() < deadline,
                    "register_region: {e}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    REGION.set((backing.as_mut_ptr() as usize, id)).unwrap();
    common::join_workers(&runtime, handles);
    let _ = std::fs::remove_file(&path);
    RESULT.get().expect("the task finished").clone().unwrap();
}
