//! A zero-copy send whose pages do not fit under `RLIMIT_MEMLOCK` gets
//! `-ENOMEM` from `SendMsgZc`. The runtime must send those bytes with plain
//! `send`s and deliver all of them; it used to drop the send, and every send
//! queued behind it, after `send_parts` had returned `Ok` (#642).
//!
//! The test lowers the soft limit to 0 after launch. From Linux 6.15 a
//! zero-copy send is charged to the limit, so every such send is over it. On
//! an earlier kernel, or in a process with `CAP_IPC_LOCK` in the initial user
//! namespace, the sends are not charged and go out zero-copy, and only
//! delivery is checked.
//!
//! One test: the limit is process-wide.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use metriken::CounterGroupMetric;
use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
};

/// Guarded bytes per send: above `send_zc_threshold`, so each send is a
/// `SendMsgZc`.
const GUARD_LEN: usize = 1024 * 1024;
const PREFIX: &[u8] = b"prefix:";
const SUFFIX: &[u8] = b":suffix";
/// Sends per connection. The second and later sends find the first's
/// `-ENOMEM` already handled, so a fallback that changed connection state
/// would show here.
const SENDS: usize = 3;

fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(7).wrapping_add(13) % 251) as u8
}

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

/// Waits for one byte, then sends `SENDS` messages of a copied prefix, a
/// guarded body and a copied suffix, fire-and-forget, and keeps the
/// connection open until the peer closes it.
struct GuardSender;

impl AsyncEventHandler for GuardSender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            if conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                == 0
            {
                return;
            }
            for _ in 0..SENDS {
                let guard = GuardBox::new(VecGuard((0..GUARD_LEN).map(pattern).collect()));
                conn.send_parts()
                    .build(|b| b.copy(PREFIX).guard(guard).copy(SUFFIX).submit())
                    .expect("guard send accepted");
            }
            while conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {}
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        GuardSender
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
    // The capability exempts a process only in the initial user namespace,
    // whose uid_map is the identity map of the whole range.
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

fn send_zc_enomem() -> u64 {
    ringline::metrics::POOL
        .counter_value(ringline::metrics::pool::SEND_ZC_ENOMEM)
        .unwrap_or(0)
}

#[test]
fn a_zero_copy_send_over_the_memlock_limit_is_sent_plain() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .recv_buffer(16, 4096)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<GuardSender>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");

    // The rings are charged at launch. Lower the soft limit now, so that
    // every page a zero-copy send pins is over it.
    let mut r: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut r) }, 0);
    r.rlim_cur = 0;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) }, 0);

    let before = send_zc_enomem();
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(b"x").unwrap();

    let len = PREFIX.len() + GUARD_LEN + SUFFIX.len();
    let mut got = vec![0u8; len];
    for n in 0..SENDS {
        stream
            .read_exact(&mut got)
            .unwrap_or_else(|e| panic!("send {n}: not delivered in full: {e}"));
        assert_eq!(&got[..PREFIX.len()], PREFIX, "send {n}: prefix");
        assert_eq!(&got[len - SUFFIX.len()..], SUFFIX, "send {n}: suffix");
        let body = &got[PREFIX.len()..len - SUFFIX.len()];
        if let Some(i) = (0..GUARD_LEN).find(|&i| body[i] != pattern(i)) {
            panic!("send {n}: body differs at byte {i}");
        }
    }

    if zero_copy_sends_are_charged() {
        // One ENOMEM per send: after it, the rest of the send (the guard
        // and the suffix are further iovecs) goes out plain rather than
        // retrying zero-copy.
        assert_eq!(
            send_zc_enomem() - before,
            SENDS as u64,
            "each send must take exactly one ENOMEM"
        );
    }

    drop(stream);
    runtime.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
