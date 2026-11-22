#![allow(clippy::manual_async_fn)]
//! Writes COUNT 4 KiB blocks through ringline::direct_io to PATH, one at a
//! time, with or without dsync. Exit status 0 only if every write wrote 4096.
//! Usage: fua_probe PATH COUNT DSYNC(0|1)
use std::future::Future;
use std::sync::Mutex;

use ringline::direct_io::{DirectIoConfig, DirectIoOpenOptions};
use ringline::{AsyncEventHandler, ConfigBuilder, Connection, RinglineBuilder};

static OUTCOME: Mutex<Option<Result<(), String>>> = Mutex::new(None);

async fn run(path: String, count: u64, dsync: bool) -> Result<(), String> {
    let file = ringline::direct_io::open_with(&path, DirectIoOpenOptions::new().dsync(dsync))
        .map_err(|e| format!("open submit: {e}"))?
        .await
        .map_err(|e| format!("open: {e}"))?;
    let mut buf = ringline::buf::AlignedBuf::zeroed(4096, 4096);
    buf.fill(0x5a);
    for i in 0..count {
        let (n, back) = ringline::direct_io::write_from(file, i * 4096, buf).await;
        let n = n.map_err(|e| format!("write {i}: {e}"))?;
        if n != 4096 {
            return Err(format!("write {i}: {n} bytes"));
        }
        buf = back;
    }
    ringline::direct_io::close(file).map_err(|e| format!("close: {e}"))
}

struct Probe;

impl AsyncEventHandler for Probe {
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<std::pin::Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let a: Vec<String> = std::env::args().collect();
            let r = run(a[1].clone(), a[2].parse().unwrap(), a[3] == "1").await;
            *OUTCOME.lock().unwrap() = Some(r);
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        Probe
    }
}

fn main() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .direct_io(DirectIoConfig::default())
        .build()
        .expect("config");
    let (rt, handles) = RinglineBuilder::new(config)
        .launch::<Probe>()
        .expect("launch");
    for h in handles {
        let _ = h.join();
    }
    drop(rt);
    match OUTCOME.lock().unwrap().take() {
        Some(Ok(())) => println!("probe ok"),
        Some(Err(e)) => {
            eprintln!("probe failed: {e}");
            std::process::exit(1)
        }
        None => {
            eprintln!("probe did not finish");
            std::process::exit(1)
        }
    }
}
