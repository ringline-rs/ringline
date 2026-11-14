#![allow(clippy::manual_async_fn)]
//! NVMe passthrough smoke test against a real device.
//!
//! Exercises the full `IORING_OP_URING_CMD` path end-to-end: device open
//! (with Identify Namespace for the block size), two `nvme_read`s of the
//! first 4 KiB (one block if blocks are larger), and an `nvme_flush`. With a
//! third argument it also writes: it reads as much at that LBA, writes a
//! pattern over it, reads the pattern back, then writes the original bytes
//! back and checks them.
//!
//! Usage (needs root for /dev/ng*):
//!
//! ```text
//! sudo target/release/examples/nvme_smoke /dev/ng0n1 [nsid] [write_lba]
//! ```
//!
//! Prints the first bytes of LBA 0 so the result can be cross-checked
//! against the block device (`dd if=/dev/nvmeXnY bs=<bs> count=1 | xxd`).

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

static DONE: AtomicBool = AtomicBool::new(false);

struct SmokeHandler;

impl AsyncEventHandler for SmokeHandler {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Server side unused — client-only mode.
            let _ = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
        }
    }

    fn on_tick(&mut self) {
        // Spawn the smoke task once, from inside the runtime.
        static SPAWNED: AtomicBool = AtomicBool::new(false);
        if SPAWNED.swap(true, Ordering::AcqRel) {
            if DONE.load(Ordering::Acquire) {
                ringline::request_shutdown().unwrap();
            }
            return;
        }

        let path = std::env::args()
            .nth(1)
            .expect("usage: nvme_smoke /dev/ngXnY [nsid] [write_lba]");
        let nsid: u32 = std::env::args()
            .nth(2)
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);
        let write_lba: Option<u64> = std::env::args().nth(3).and_then(|s| s.parse().ok());
        let _ = ringline::spawn(async move {
            let run = async {
                let device = ringline::open_nvme_device(&path, nsid)?;
                let bs = ringline::nvme_lba_size(device)?;
                println!("opened {path} nsid={nsid} block_size={bs}");

                // 4 KiB reads from LBA 0 into page-aligned buffers.
                // At least one block, so a block size above 4 KiB reads one.
                let blocks: u16 = (4096 / bs).max(1) as u16;
                let len = blocks as usize * bs as usize;
                let buf = ringline::buf::AlignedBuf::with_capacity(len, 4096);
                let (res_a, a) = ringline::nvme_read(device, 0, blocks, buf).await;
                println!("nvme_read #1 (LBA 0, {blocks} blocks): {:?}", res_a?);
                let buf = ringline::buf::AlignedBuf::with_capacity(len, 4096);
                let (res_b, b) = ringline::nvme_read(device, 0, blocks, buf).await;
                println!("nvme_read #2 (LBA 0, {blocks} blocks): {:?}", res_b?);

                if a[..] != b[..] {
                    return Err(std::io::Error::other("re-read of LBA 0 differs"));
                }
                let nonzero = a.iter().filter(|&&x| x != 0).count();
                println!(
                    "LBA0[0..32] = {:02x?}  (nonzero bytes in 4KiB: {nonzero})",
                    &a[..32]
                );

                if let Some(lba) = write_lba {
                    write_and_restore(device, lba, blocks, len).await?;
                }

                let res_f = ringline::nvme_flush(device)?.await?;
                println!("nvme_flush: {res_f:?}");
                Ok::<(), std::io::Error>(())
            };
            match run.await {
                Ok(()) => println!("NVME SMOKE: PASS"),
                Err(e) => {
                    println!("NVME SMOKE: FAIL: {e}");
                    std::process::exit(1);
                }
            }
            DONE.store(true, Ordering::Release);
        });
    }

    fn create_for_worker(_id: usize) -> Self {
        SmokeHandler
    }
}

fn main() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .nvme(ringline::NvmeConfig::default())
        .build()
        .expect("valid config");

    let (_runtime, handles) = RinglineBuilder::new(config)
        .launch::<SmokeHandler>()
        .expect("launch failed");
    for h in handles {
        h.join().unwrap().unwrap();
    }
}

/// Read `len` bytes (`blocks` blocks) at `lba`, write a pattern over them and
/// read it back, then write the original bytes back and read those back.
async fn write_and_restore(
    device: ringline::nvme::NvmeDevice,
    lba: u64,
    blocks: u16,
    len: usize,
) -> std::io::Result<()> {
    use ringline::buf::AlignedBuf;
    let read = |what: &'static str| async move {
        let (res, buf) =
            ringline::nvme_read(device, lba, blocks, AlignedBuf::with_capacity(len, 4096)).await;
        let n = res?;
        println!("nvme_read ({what}, LBA {lba}): {n} bytes");
        if n != len || buf.len() != len {
            return Err(std::io::Error::other(format!("{what}: read {n} bytes")));
        }
        Ok::<_, std::io::Error>(buf)
    };
    let write = |buf: bytes::Bytes, what: &'static str| async move {
        let (res, _) = ringline::nvme_write(device, lba, blocks, buf).await;
        let n = res?;
        println!("nvme_write ({what}, LBA {lba}): {n} bytes");
        if n != len {
            return Err(std::io::Error::other(format!("{what}: wrote {n} bytes")));
        }
        Ok::<_, std::io::Error>(())
    };

    let original = read("original").await?.freeze();
    let mut pattern = AlignedBuf::with_capacity(len, 4096);
    for i in 0..len as u32 {
        pattern.extend_from_slice(&[(i.wrapping_mul(31) ^ 0x5a) as u8]);
    }
    let pattern = pattern.freeze();
    write(pattern.clone(), "pattern").await?;
    let back = read("pattern").await?;
    let pattern_ok = back[..] == pattern[..];
    write(original.clone(), "restore").await?;
    let restored = read("restored").await?;
    if !pattern_ok {
        return Err(std::io::Error::other("the pattern read back differs"));
    }
    if restored[..] != original[..] {
        return Err(std::io::Error::other(
            "the restored block differs from the original",
        ));
    }
    println!("NVME WRITE: PASS (LBA {lba} restored)");
    Ok(())
}
