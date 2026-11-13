//! When `RLIMIT_MEMLOCK` is too low for the default rings, launch lowers the
//! queue and connection sizes left at their defaults until the rings fit,
//! and the runtime serves at those sizes. A CQ set on the builder is kept,
//! and launch refuses instead.
//!
//! One test, sequential: lowering the hard limit is irreversible for the
//! process. The kernel compares the limit with what every process of this
//! user has charged, so `.config/nextest.toml` runs this binary alone.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, Error, ParseResult, RinglineBuilder};

/// The limit, the systemd default.
const LIMIT: u64 = 8 * 1024 * 1024;

struct Echo;

impl AsyncEventHandler for Echo {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            loop {
                let mut echo = Vec::new();
                let n = conn
                    .with_data(|data| {
                        echo.extend_from_slice(data);
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    return;
                }
                let _ = conn.send_nowait(&echo);
            }
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Echo
    }
}

/// Four workers, with `max_connections`, `sq_entries` and `cq_entries` left
/// at their defaults.
fn builder() -> ConfigBuilder {
    ConfigBuilder::new()
        .workers(4)
        .pin_to_core(false)
        .send_pool(16, 16384)
}

fn kernel() -> (u32, u32) {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap();
    let mut parts = release.trim().split(|c: char| !c.is_ascii_digit());
    let major = parts.next().unwrap().parse().unwrap();
    let minor = parts.next().unwrap().parse().unwrap();
    (major, minor)
}

fn has_cap_ipc_lock() -> bool {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let hex = status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .unwrap()
        .trim();
    u64::from_str_radix(hex, 16).unwrap() & (1 << 14) != 0
}

fn set_memlock(soft: u64, hard: u64) {
    let r = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    assert_eq!(
        unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &r) },
        0,
        "setrlimit: {}",
        std::io::Error::last_os_error()
    );
}

type Launched = (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), Error>>>,
);

/// Launch the config `make` builds, retrying an `ENOMEM` from ring setup for
/// up to 5 s: a ring dropped earlier, in this process or another, is
/// uncharged asynchronously.
fn launch(make: impl Fn() -> ConfigBuilder) -> Result<Launched, Error> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = RinglineBuilder::new(make().build().unwrap())
            .bind("127.0.0.1:0".parse().unwrap())
            .launch::<Echo>();
        match result {
            Err(Error::RingSetup(ref text))
                if text.contains("ENOMEM") && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(50));
            }
            other => return other,
        }
    }
}

#[test]
fn launch_fits_default_rings_to_a_low_memlock_limit() {
    // A root or CAP_IPC_LOCK process is not charged; nothing would be fitted.
    assert!(
        unsafe { libc::geteuid() } != 0 && !has_cap_ipc_lock(),
        "run this test unprivileged"
    );
    if kernel() < (6, 14) {
        // Rings are not charged before 6.14: the defaults launch unchanged.
        let (runtime, handles) = launch(builder).expect("launch");
        assert_eq!(runtime.cq_entries(), 65536);
        runtime.shutdown();
        for h in handles {
            h.join().unwrap().unwrap();
        }
        return;
    }
    assert_eq!(
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) },
        4096,
        "the sizes below assume 4 KiB pages"
    );
    set_memlock(LIMIT, LIMIT);

    // A CQ set on the builder is kept: four workers at 65536 entries need
    // about 10 MiB, so launch refuses.
    let err = launch(|| builder().cq_entries(65536))
        .err()
        .expect("launch must refuse a CQ it may not lower");
    assert!(
        matches!(err, Error::ResourceLimit(_)),
        "expected ResourceLimit, got {err:?}"
    );

    // A max_connections set on the builder above what a smaller CQ holds in
    // the defaults' proportion stops the fit, and the error says so: 16384
    // connections, as the benchmark servers set, need a CQ of 65536.
    let err = launch(|| builder().max_connections(16384).sq_entries(256))
        .err()
        .expect("launch must refuse when the connections need the full CQ");
    let text = err.to_string();
    assert!(matches!(err, Error::ResourceLimit(_)), "{err:?}");
    assert!(
        text.contains("max_connections 16384") && text.contains("65536 entries"),
        "{text}"
    );

    // Left at the defaults, the rings are fitted: 32768 CQ entries is the
    // largest that fits four workers in 8 MiB, with the SQ and the
    // connection limit in the defaults' proportion.
    let (runtime, handles) = launch(builder).expect("launch with fitted rings");
    assert_eq!(
        (
            runtime.max_connections(),
            runtime.sq_entries(),
            runtime.cq_entries()
        ),
        (8000, 2048, 32768)
    );

    let addr = runtime.bound_addr().expect("bound address");
    let mut client = TcpStream::connect(addr).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    client.write_all(b"hello").unwrap();
    let mut echoed = [0u8; 5];
    client.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hello");
    drop(client);

    runtime.shutdown();
    for h in handles {
        h.join().unwrap().unwrap();
    }
}
