//! A chain whose zero-copy part gets `-ENOMEM` fails, so the runtime closes the
//! connection. Otherwise a later send reaches the peer after the bytes the chain
//! lost, and a `send_chain_nowait` or a dropped `send_chain` future reports
//! nothing (#734).
//!
//! The test lowers the soft `RLIMIT_MEMLOCK` to 0 after launch, as
//! `zc_send_enomem.rs` does. From Linux 6.15 a zero-copy send is charged to the
//! limit. On an earlier kernel, or with `CAP_IPC_LOCK` in the initial user
//! namespace, the send goes out zero-copy and the stream arrives whole.
//!
//! One test: the limit is process-wide.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
};

const GUARD_LEN: usize = 1024 * 1024;
const LATER_SEND: &[u8] = b"sent after the chain";

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

/// Waits for one byte, sends a chain with a zero-copy part, then plain sends.
/// The byte picks the chain: `n` for `send_chain_nowait`, `d` for a dropped
/// `send_chain` future.
struct ChainSender;

impl AsyncEventHandler for ChainSender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut mode = 0;
            if conn
                .with_data(|data| {
                    mode = data[0];
                    ParseResult::Consumed(data.len())
                })
                .await
                == 0
            {
                return;
            }
            let guard = GuardBox::new(VecGuard(vec![7; GUARD_LEN]));
            if mode == b'n' {
                conn.send_chain_nowait(|c| c.parts().guard(guard).add().finish())
                    .expect("chain accepted");
            } else {
                drop(
                    conn.send_chain(|c| c.parts().guard(guard).add().finish())
                        .expect("chain accepted"),
                );
            }
            // One send queued behind the chain, and one after it has finished.
            conn.send_nowait(LATER_SEND).expect("later send accepted");
            ringline::sleep(Duration::from_millis(50)).await;
            let _ = conn.send_nowait(LATER_SEND);
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ChainSender
    }
}

/// Whether a zero-copy send is charged to `RLIMIT_MEMLOCK` here: Linux 6.15
/// or later, and no `CAP_IPC_LOCK` in the initial user namespace.
fn zero_copy_sends_are_charged() -> bool {
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::uname(&mut uts) }, 0);
    let release = unsafe { std::ffi::CStr::from_ptr(uts.release.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    let mut parts = release
        .split(|c: char| !c.is_ascii_digit())
        .map(|p| p.parse::<u32>().unwrap_or(0));
    let version = (parts.next().unwrap_or(0), parts.next().unwrap_or(0));
    if version < (6, 15) {
        return false;
    }
    let initial_ns = std::fs::read_to_string("/proc/self/uid_map")
        .map(|m| m.split_whitespace().collect::<Vec<_>>() == ["0", "0", "4294967295"])
        .unwrap_or(false);
    let cap_ipc_lock = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("CapEff:"))
                .and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
        })
        .is_some_and(|caps| caps & (1 << 14) != 0);
    !(initial_ns && cap_ipc_lock)
}

#[test]
fn a_failed_chain_closes_the_connection() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<ChainSender>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");

    let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) }, 0);
    r.rlim_cur = 0;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) }, 0);

    let charged = zero_copy_sends_are_charged();
    for mode in *b"nd" {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(&[mode]).unwrap();

        let mut received = Vec::new();
        let mut buf = [0u8; 65536];
        let closed = loop {
            match stream.read(&mut buf) {
                Ok(0) => break true,
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::ConnectionReset => break true,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    break false;
                }
                Err(e) => panic!("read: {e}"),
            }
            if !charged && received.len() == GUARD_LEN + 2 * LATER_SEND.len() {
                break false;
            }
        };

        if charged {
            assert!(closed, "the connection stayed open after the chain failed");
            assert!(
                received.is_empty(),
                "{} bytes reached the peer after the failed chain",
                received.len()
            );
        } else {
            assert_eq!(received.len(), GUARD_LEN + 2 * LATER_SEND.len());
            assert!(received.ends_with(LATER_SEND));
        }
    }

    runtime.shutdown();
    for handle in handles {
        handle.join().expect("worker panicked").expect("worker");
    }
}
