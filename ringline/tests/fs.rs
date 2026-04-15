#![allow(clippy::manual_async_fn)]
#![cfg(has_io_uring)]
//! Integration tests for the async fs module.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};

use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder};

fn test_config() -> Config {
    let mut config = Config::default();
    config.worker.threads = 1;
    config.worker.pin_to_core = false;
    config.sq_entries = 64;
    config.recv_buffer.ring_size = 64;
    config.recv_buffer.buffer_size = 4096;
    config.max_connections = 64;
    config.send_copy_count = 64;
    config.resolver_threads = 0;
    config
}

fn temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("ringline-fs-test-{}-{name}", std::process::id()))
}

// ── Create + write + read ───────────────────────────────────────────

static FS_READ_RESULT: AtomicU32 = AtomicU32::new(0);

struct FsReadWriteHandler;

impl AsyncEventHandler for FsReadWriteHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_path("rw.txt");

            // Create and write.
            let file = ringline::fs::create(&path).unwrap().await.unwrap();
            let data = b"hello ringline fs";
            let n = unsafe {
                ringline::fs::write(file, 0, data.as_ptr(), data.len() as u32)
                    .unwrap()
                    .await
            };
            assert!(n.is_ok());

            // Fsync.
            ringline::fs::fsync(file).unwrap().await.ok();

            // Close and reopen for read.
            ringline::fs::close(file).unwrap();

            let file = ringline::fs::open(&path, ringline::fs::OpenFlags::READ, 0)
                .unwrap()
                .await
                .unwrap();
            let mut buf = [0u8; 64];
            let result = unsafe {
                ringline::fs::read(file, 0, buf.as_mut_ptr(), buf.len() as u32)
                    .unwrap()
                    .await
            };
            match result {
                Ok(n) if n > 0 && &buf[..n as usize] == b"hello ringline fs" => {
                    FS_READ_RESULT.store(1, Ordering::SeqCst);
                }
                _ => {}
            }

            ringline::fs::close(file).unwrap();
            let _ = std::fs::remove_file(&path);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsReadWriteHandler
    }
}

#[test]
fn fs_create_write_read() {
    FS_READ_RESULT.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsReadWriteHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(FS_READ_RESULT.load(Ordering::SeqCst), 1);
}

// ── Stat ────────────────────────────────────────────────────────────

static FS_STAT_RESULT: AtomicU32 = AtomicU32::new(0);

struct FsStatHandler;

impl AsyncEventHandler for FsStatHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_path("stat.txt");

            // Create a file with known content.
            std::fs::write(&path, b"stat test data").unwrap();

            let meta = ringline::fs::stat(&path).unwrap().await.unwrap();
            if meta.size == 14 && meta.is_file && !meta.is_dir {
                FS_STAT_RESULT.store(1, Ordering::SeqCst);
            }

            let _ = std::fs::remove_file(&path);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsStatHandler
    }
}

#[test]
fn fs_stat_file() {
    FS_STAT_RESULT.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsStatHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(FS_STAT_RESULT.load(Ordering::SeqCst), 1);
}

// ── Rename ──────────────────────────────────────────────────────────

static FS_RENAME_RESULT: AtomicU32 = AtomicU32::new(0);

struct FsRenameHandler;

impl AsyncEventHandler for FsRenameHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let old = temp_path("rename-old.txt");
            let new = temp_path("rename-new.txt");

            std::fs::write(&old, b"rename me").unwrap();
            let _ = std::fs::remove_file(&new);

            let result = ringline::fs::rename(&old, &new).unwrap().await;
            if result.is_ok() && !old.exists() && new.exists() {
                let data = std::fs::read(&new).unwrap();
                if data == b"rename me" {
                    FS_RENAME_RESULT.store(1, Ordering::SeqCst);
                }
            }

            let _ = std::fs::remove_file(&new);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsRenameHandler
    }
}

#[test]
fn fs_rename_file() {
    FS_RENAME_RESULT.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsRenameHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(FS_RENAME_RESULT.load(Ordering::SeqCst), 1);
}

// ── Remove ──────────────────────────────────────────────────────────

static FS_REMOVE_RESULT: AtomicU32 = AtomicU32::new(0);

struct FsRemoveHandler;

impl AsyncEventHandler for FsRemoveHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_path("remove.txt");
            std::fs::write(&path, b"delete me").unwrap();

            let result = ringline::fs::remove(&path).unwrap().await;
            if result.is_ok() && !path.exists() {
                FS_REMOVE_RESULT.store(1, Ordering::SeqCst);
            }

            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsRemoveHandler
    }
}

#[test]
fn fs_remove_file() {
    FS_REMOVE_RESULT.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsRemoveHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(FS_REMOVE_RESULT.load(Ordering::SeqCst), 1);
}

// ── Mkdir ───────────────────────────────────────────────────────────

static FS_MKDIR_RESULT: AtomicU32 = AtomicU32::new(0);

struct FsMkdirHandler;

impl AsyncEventHandler for FsMkdirHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_path("testdir");
            let _ = std::fs::remove_dir(&path);

            let result = ringline::fs::mkdir(&path, 0o755).unwrap().await;
            if result.is_ok() && path.exists() {
                let meta = ringline::fs::stat(&path).unwrap().await.unwrap();
                if meta.is_dir {
                    FS_MKDIR_RESULT.store(1, Ordering::SeqCst);
                }
            }

            let _ = std::fs::remove_dir(&path);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: ConnCtx) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsMkdirHandler
    }
}

#[test]
fn fs_mkdir_and_stat() {
    FS_MKDIR_RESULT.store(0, Ordering::SeqCst);

    let (_shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsMkdirHandler>()
        .expect("launch failed");

    for h in handles {
        h.join().unwrap().unwrap();
    }
    assert_eq!(FS_MKDIR_RESULT.load(Ordering::SeqCst), 1);
}
