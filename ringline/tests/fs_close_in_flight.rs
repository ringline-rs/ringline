//! `fs::close` with operations on the file still in flight (#859).
//!
//! On io_uring, an operation issued in the same task poll as the close is
//! still in the user-space SQ when `close` returns. The close is deferred
//! until the last such operation completes, so the operation finds the file.
//! On mio each queued operation holds its own reference to the fd.

#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use ringline::fs::FsConfig;
use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

/// The tests share `OUTCOME`, and `cargo test` runs them on parallel threads.
static SERIAL: Mutex<()> = Mutex::new(());
static OUTCOME: Mutex<Option<String>> = Mutex::new(None);

/// One file slot, so a slot the close did not free is seen at the next open.
fn config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .resolver_threads(0)
        .fs(FsConfig::default().max_files(1).max_commands_in_flight(8))
        .build()
        .expect("valid config")
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("ringline-close-{}-{name}", std::process::id()))
}

fn finish(outcome: String) {
    *OUTCOME.lock().unwrap() = Some(outcome);
    ringline::request_shutdown().ok();
}

fn run<H: AsyncEventHandler>() -> String {
    *OUTCOME.lock().unwrap() = None;
    let (runtime, handles) = RinglineBuilder::new(config())
        .launch::<H>()
        .expect("launch");
    common::join_workers(&runtime, handles);
    OUTCOME
        .lock()
        .unwrap()
        .take()
        .expect("on_start did not finish")
}

/// Writes, closes without awaiting the write, then awaits it; then checks the
/// closed handle is refused and the slot is free for another file.
struct WriteThenClose;

impl AsyncEventHandler for WriteThenClose {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_path("write-then-close");
            let other = temp_path("other");
            let file = ringline::fs::create(&path).unwrap().await.unwrap();
            // Both calls in one poll: the write is issued, then the close.
            let write = ringline::fs::write_from(file, 0, bytes::BytesMut::from(&b"close"[..]));
            let closed = ringline::fs::close(file);
            // The handle is refused at once, before the write completes.
            let reuse = ringline::fs::fsync(file).map(|_| ());
            let (written, _buf) = write.await;
            let on_disk = std::fs::read(&path).unwrap_or_default();
            // The one slot is free again once the write has completed.
            let reopened = match ringline::fs::create(&other) {
                Ok(open) => open.await.map(|f| {
                    let _ = ringline::fs::close(f);
                }),
                Err(e) => Err(e),
            };
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_file(&other);
            finish(format!(
                "close={closed:?} reuse_ok={} write={written:?} on_disk={:?} reopen={reopened:?}",
                reuse.is_ok(),
                String::from_utf8_lossy(&on_disk),
            ));
        }))
    }
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        WriteThenClose
    }
}

#[test]
fn a_write_issued_before_close_in_the_same_poll_lands() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let out = run::<WriteThenClose>();
    assert!(out.contains("close=Ok(())"), "{out}");
    assert!(
        out.contains("write=Ok(5)"),
        "the write did not complete: {out}"
    );
    assert!(
        out.contains("on_disk=\"close\""),
        "the write did not reach the file: {out}"
    );
}

#[test]
fn a_closed_handle_is_refused_while_its_write_is_in_flight() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let out = run::<WriteThenClose>();
    assert!(
        out.contains("reuse_ok=false"),
        "an operation on the closed handle was accepted: {out}"
    );
}

#[test]
fn the_slot_is_free_once_the_deferred_close_finishes() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let out = run::<WriteThenClose>();
    assert!(
        out.contains("reopen=Ok(())"),
        "the closed file's slot was not released: {out}"
    );
}
