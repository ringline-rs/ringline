//! A send of one guard and a send of three guards from one registered region
//! deliver their bytes in order. Each is submitted from the region's buffer
//! exactly when the kernel probe enabled that kind of send
//! (`Runtime::fixed_buffer_sends`). The op
//! each kind of send is pushed as is checked by the lib test
//! `a_guard_only_send_from_one_region_uses_its_buffer`.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::Read;
use std::net::TcpStream;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, FixedBufferSends, GuardBox, MemoryRegion,
    RegionId, RinglineBuilder, SendGuard,
};

const REGION_LEN: usize = 64 << 10;
/// Each guard's length, and the order the guards are sent in, by offset: the
/// first send is the first part alone, the second the rest.
const PART: usize = 16 << 10;
const ORDER: [usize; 4] = [1, 2, 0, 3];

/// The leaked memory the test registers, and the id the runtime gave it.
static REGION: OnceLock<(usize, RegionId)> = OnceLock::new();

struct RegionGuard {
    ptr: usize,
    region: RegionId,
}

impl SendGuard for RegionGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.ptr as *const u8, PART as u32)
    }
    fn region(&self) -> RegionId {
        self.region
    }
}

struct Handler;

impl AsyncEventHandler for Handler {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut conn = conn;
            let &(base, region) = REGION.get().expect("registered before the connect");
            let guard = |i: usize| {
                ringline::SendPart::Guard(GuardBox::new(RegionGuard {
                    ptr: base + i * PART,
                    region,
                }))
            };
            for parts in [&ORDER[..1], &ORDER[1..]] {
                let parts = parts.iter().map(|&i| guard(i)).collect();
                let (_, sent) = conn
                    .send_parts()
                    .submit_batch(parts)
                    .expect("send submitted");
                let _ = sent.await;
            }
            // Hold the connection until the client has read the reply and
            // closed.
            let _ = conn
                .with_data(|d| ringline::ParseResult::Consumed(d.len()))
                .await;
            ringline::request_shutdown().ok();
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Handler
    }
}

fn sent_fixed() -> u64 {
    ringline::metrics::RING
        .value(ringline::metrics::ring::SEND_FIXED_BUFFER)
        .unwrap_or(0)
}

#[test]
fn guard_sends_from_one_region_arrive_in_order() {
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
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Handler>()
        .expect("launch failed");
    let addr = runtime.bound_addr().expect("bound");

    let backing: &'static mut [u8] = Box::leak(vec![0u8; REGION_LEN].into_boxed_slice());
    for (i, b) in backing.iter_mut().enumerate() {
        *b = (i / PART) as u8 ^ (i % 251) as u8;
    }
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
    REGION.set((backing.as_ptr() as usize, id)).unwrap();
    let status = runtime.fixed_buffer_sends();
    eprintln!("fixed-buffer sends: {status:?}");
    // A run on a known kernel names the result it expects; `decided` accepts
    // any result but `Inconclusive`.
    match std::env::var("RINGLINE_EXPECT_FIXED_SEND").as_deref() {
        Ok("decided") => assert!(
            !matches!(status, FixedBufferSends::Inconclusive(_)),
            "the probe could not decide: {status:?}"
        ),
        Ok(want) => assert_eq!(format!("{status:?}"), want, "the probe's result"),
        Err(_) => {}
    }
    let before = sent_fixed();

    let mut client = TcpStream::connect(addr).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut got = vec![0u8; ORDER.len() * PART];
    client.read_exact(&mut got).expect("the reply");
    drop(client);

    let want: Vec<u8> = ORDER
        .iter()
        .flat_map(|&i| backing[i * PART..(i + 1) * PART].iter().copied())
        .collect();
    assert!(got == want, "the bytes arrived as sent, in part order");
    let fixed = sent_fixed() - before;
    let want = match status {
        FixedBufferSends::Enabled { multi_guard } => 1 + u64::from(multi_guard),
        _ => 0,
    };
    assert_eq!(
        fixed, want,
        "{status:?}: sends that named the region's buffer"
    );
    common::join_workers(&runtime, handles);
}
