#![allow(clippy::manual_async_fn)]
//! Integration tests for the async fs module.

mod common;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};

use ringline::{AsyncEventHandler, Config, ConfigBuilder, Connection, RinglineBuilder};

fn test_config_builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(64)
        .send_pool(64, 16384)
        .resolver_threads(0)
}

fn test_config() -> Config {
    test_config_builder().build().expect("valid config")
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
            let (n, _) = ringline::fs::write_from(file, 0, bytes::Bytes::from_static(data)).await;
            assert!(n.is_ok());

            // Fsync.
            ringline::fs::fsync(file).unwrap().await.ok();

            // Close and reopen for read.
            ringline::fs::close(file).unwrap();

            let file = ringline::fs::open(&path, ringline::fs::OpenFlags::READ, 0)
                .unwrap()
                .await
                .unwrap();
            let (result, buf) = ringline::fs::read_into(file, 0, Vec::with_capacity(64)).await;
            match result {
                Ok(n) if n > 0 && &buf[..n] == b"hello ringline fs" => {
                    FS_READ_RESULT.store(1, Ordering::SeqCst);
                }
                _ => {}
            }

            ringline::fs::close(file).unwrap();
            let _ = std::fs::remove_file(&path);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsReadWriteHandler
    }
}

#[test]
fn fs_create_write_read() {
    FS_READ_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsReadWriteHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
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

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsStatHandler
    }
}

#[test]
fn fs_stat_file() {
    FS_STAT_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsStatHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
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

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsRenameHandler
    }
}

#[test]
fn fs_rename_file() {
    FS_RENAME_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsRenameHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
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

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsRemoveHandler
    }
}

#[test]
fn fs_remove_file() {
    FS_REMOVE_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsRemoveHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
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

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsMkdirHandler
    }
}

#[test]
fn fs_mkdir_and_stat() {
    FS_MKDIR_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsMkdirHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(FS_MKDIR_RESULT.load(Ordering::SeqCst), 1);
}

// ── Safe owned-buffer API: read_into / write_from ───────────────────

static FS_SAFE_RESULT: AtomicU32 = AtomicU32::new(0);

struct FsSafeRoundtripHandler;

impl AsyncEventHandler for FsSafeRoundtripHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_path("safe-rw.txt");
            let payload: &[u8] = b"safe api roundtrip data";

            // write_from: hand the runtime an owned BytesMut, get it back.
            let file = ringline::fs::create(&path).unwrap().await.unwrap();
            let mut wbuf = bytes::BytesMut::with_capacity(payload.len());
            wbuf.extend_from_slice(payload);
            let (wres, wbuf) = ringline::fs::write_from(file, 0, wbuf).await;
            assert_eq!(wres.unwrap(), payload.len());
            // Buffer is returned with len unchanged.
            assert_eq!(&wbuf[..], payload);
            ringline::fs::close(file).unwrap();

            // read_into: kernel fills spare capacity, future yields updated buf.
            let file = ringline::fs::open(&path, ringline::fs::OpenFlags::READ, 0)
                .unwrap()
                .await
                .unwrap();
            let rbuf = bytes::BytesMut::with_capacity(64);
            let (rres, rbuf) = ringline::fs::read_into(file, 0, rbuf).await;
            let n = rres.unwrap();
            if n == payload.len() && &rbuf[..n] == payload {
                FS_SAFE_RESULT.store(1, Ordering::SeqCst);
            }

            ringline::fs::close(file).unwrap();
            let _ = std::fs::remove_file(&path);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsSafeRoundtripHandler
    }
}

#[test]
fn fs_safe_api_roundtrip() {
    FS_SAFE_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsSafeRoundtripHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(FS_SAFE_RESULT.load(Ordering::SeqCst), 1);
}

// ── Drop in-flight: buffer must be parked, no UAF, follow-up read works ─

static FS_DROP_RESULT: AtomicU32 = AtomicU32::new(0);

struct FsDropInFlightHandler;

impl AsyncEventHandler for FsDropInFlightHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let path = temp_path("safe-drop.txt");
            let payload: &[u8] = b"abandon the first read";

            std::fs::write(&path, payload).unwrap();
            let file = ringline::fs::open(&path, ringline::fs::OpenFlags::READ, 0)
                .unwrap()
                .await
                .unwrap();

            // Submit a read and immediately drop the future without awaiting.
            // The buffer must be parked in the runtime until the kernel CQE
            // arrives; if it isn't, the kernel may scribble into freed memory.
            {
                let _fut =
                    ringline::fs::read_into(file, 0, bytes::BytesMut::with_capacity(payload.len()));
                // _fut dropped here without poll.
            }

            // Issue a second read on the same file. If the graveyard logic
            // is broken, this is where memory corruption would surface.
            let rbuf = bytes::BytesMut::with_capacity(payload.len());
            let (rres, rbuf) = ringline::fs::read_into(file, 0, rbuf).await;
            let n = rres.unwrap();
            if n == payload.len() && &rbuf[..n] == payload {
                FS_DROP_RESULT.store(1, Ordering::SeqCst);
            }

            ringline::fs::close(file).unwrap();
            let _ = std::fs::remove_file(&path);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsDropInFlightHandler
    }
}

#[test]
fn fs_safe_api_drop_in_flight() {
    FS_DROP_RESULT.store(0, Ordering::SeqCst);

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsDropInFlightHandler>()
        .expect("launch failed");

    common::join_workers(&shutdown, handles);
    assert_eq!(FS_DROP_RESULT.load(Ordering::SeqCst), 1);
}

// ── stat and symlink_metadata on a symbolic link ────────────────────

static FS_SYMLINK_RESULT: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();

async fn stat_and_lstat_a_link(
    target: &std::path::Path,
    link: &std::path::Path,
) -> Result<(), String> {
    let followed = ringline::fs::stat(link)
        .map_err(|e| format!("stat submit: {e}"))?
        .await
        .map_err(|e| format!("stat: {e}"))?;
    if !followed.is_file || followed.is_symlink || followed.size != 5 {
        return Err(format!(
            "stat(link) did not report the target: {followed:?}"
        ));
    }
    let own = ringline::fs::symlink_metadata(link)
        .map_err(|e| format!("symlink_metadata submit: {e}"))?
        .await
        .map_err(|e| format!("symlink_metadata: {e}"))?;
    // S_IFMT and S_IFLNK, which libc types as u32 on Linux and u16 on macOS.
    if !own.is_symlink || own.is_file || own.mode & 0o170000 != 0o120000 {
        return Err(format!(
            "symlink_metadata(link) did not report a link: {own:?}"
        ));
    }
    if own.size != target.as_os_str().len() as u64 {
        return Err(format!(
            "symlink_metadata(link) size {} is not the target path's length {}",
            own.size,
            target.as_os_str().len()
        ));
    }
    let dangling = link.with_extension("dangling");
    match ringline::fs::stat(&dangling)
        .map_err(|e| format!("stat(dangling) submit: {e}"))?
        .await
    {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        other => return Err(format!("stat(dangling) did not fail NotFound: {other:?}")),
    }
    let own = ringline::fs::symlink_metadata(&dangling)
        .map_err(|e| format!("symlink_metadata(dangling) submit: {e}"))?
        .await
        .map_err(|e| format!("symlink_metadata(dangling): {e}"))?;
    if !own.is_symlink {
        return Err(format!(
            "symlink_metadata(dangling) did not report a link: {own:?}"
        ));
    }
    let plain = ringline::fs::symlink_metadata(target)
        .map_err(|e| format!("symlink_metadata(target) submit: {e}"))?
        .await
        .map_err(|e| format!("symlink_metadata(target): {e}"))?;
    if !plain.is_file || plain.is_symlink || plain.size != 5 {
        return Err(format!(
            "symlink_metadata(target) differs from stat: {plain:?}"
        ));
    }
    Ok(())
}

fn symlink_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    (temp_path("symlink-target"), temp_path("symlink-link"))
}

struct FsSymlinkHandler;

impl AsyncEventHandler for FsSymlinkHandler {
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            let (target, link) = symlink_paths();
            let _ = FS_SYMLINK_RESULT.set(stat_and_lstat_a_link(&target, &link).await);
            ringline::request_shutdown().ok();
        }))
    }

    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }
    fn create_for_worker(_id: usize) -> Self {
        FsSymlinkHandler
    }
}

#[test]
fn stat_follows_a_symlink_and_symlink_metadata_does_not() {
    let (target, link) = symlink_paths();
    let _ = std::fs::remove_file(&link);
    std::fs::write(&target, b"hello").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let dangling = link.with_extension("dangling");
    let _ = std::fs::remove_file(&dangling);
    std::os::unix::fs::symlink(temp_path("symlink-missing"), &dangling).unwrap();

    let (shutdown, handles) = RinglineBuilder::new(test_config())
        .launch::<FsSymlinkHandler>()
        .expect("launch failed");
    common::join_workers(&shutdown, handles);
    let _ = std::fs::remove_file(&link);
    let _ = std::fs::remove_file(&dangling);
    let _ = std::fs::remove_file(&target);
    FS_SYMLINK_RESULT
        .get()
        .expect("the task finished")
        .clone()
        .unwrap();
}
