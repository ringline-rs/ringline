//! Guard sends on a Unix-domain connection arrive and leave it open. On
//! io_uring a Unix socket refuses `SENDMSG_ZC` with `EOPNOTSUPP`, so these go
//! out as plain `sendmsg`s (#829). On mio guard sends are copied.

#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard, SendPart,
};

/// Larger than a Linux Unix socket's default send buffer (208 KiB). The peer
/// waits before it reads, so the kernel takes the send in parts.
const BIG: usize = 1 << 20;
/// Above the default `send_zc_threshold` (4096).
const SMALL: usize = 8192;
const PREFIX: &[u8] = b"prefix:";
const SUFFIX: &[u8] = b":suffix";
#[cfg(has_io_uring)]
const TAIL: &[u8] = b"after the chain";

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

/// What the server sends, in order.
fn expected() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(PREFIX);
    out.extend_from_slice(&pattern(BIG, 1));
    out.extend_from_slice(SUFFIX);
    out.extend_from_slice(&pattern(SMALL, 2));
    #[cfg(has_io_uring)]
    {
        out.extend_from_slice(&pattern(SMALL, 3));
        out.extend_from_slice(TAIL);
    }
    out.extend_from_slice(b"ok");
    out
}

/// On a byte from the peer: a copy, guard, copy `send_parts`; a guard-only
/// `send_parts`; on io_uring a `send_chain` of a guard part and a copied tail;
/// then, on a second byte, "ok".
struct GuardSender;

impl AsyncEventHandler for GuardSender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            let big = GuardBox::new(VecGuard(pattern(BIG, 1)));
            let (_, mixed) = conn
                .send_parts()
                .submit_batch_await(vec![
                    SendPart::Copy(PREFIX),
                    SendPart::Guard(big),
                    SendPart::Copy(SUFFIX),
                ])
                .expect("mixed guard send accepted");
            let small = GuardBox::new(VecGuard(pattern(SMALL, 2)));
            let (_, guard_only) = conn
                .send_parts()
                .submit_batch_await(vec![SendPart::Guard(small)])
                .expect("guard-only send accepted");
            // A chain starts only once the earlier sends have completed.
            mixed.await.expect("mixed guard send");
            guard_only.await.expect("guard-only send");
            // `send_chain` is io_uring only.
            #[cfg(has_io_uring)]
            {
                let chained = GuardBox::new(VecGuard(pattern(SMALL, 3)));
                conn.send_chain(|c| c.parts().guard(chained).add().copy(TAIL).finish())
                    .expect("chain accepted")
                    .await
                    .expect("chain sent");
            }
            if conn
                .with_data(|data| ParseResult::Consumed(data.len()))
                .await
                > 0
            {
                conn.send(b"ok").expect("reply accepted").await.ok();
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

#[test]
fn guard_sends_on_a_unix_connection_arrive_and_keep_it_open() {
    let dir = std::env::temp_dir().join(format!("ringline-829-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("sock");
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind_unix(&path)
        .launch::<GuardSender>()
        .expect("launch");

    let mut peer = UnixStream::connect(&path).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    peer.write_all(b"x").unwrap();
    // Let the send fill the socket before reading, so the rest of it is sent
    // after a partial send.
    std::thread::sleep(Duration::from_millis(100));

    let want = expected();
    let before_ok = want.len() - 2;
    let mut got = Vec::with_capacity(want.len());
    let mut buf = [0u8; 65536];
    while got.len() < before_ok {
        let n = peer
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("read after {} bytes: {e}", got.len()));
        assert!(n > 0, "the connection closed after {} bytes", got.len());
        got.extend_from_slice(&buf[..n]);
    }
    // The connection is still open: it answers a second byte.
    peer.write_all(b"y").unwrap();
    while got.len() < want.len() {
        let n = peer
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("read after {} bytes: {e}", got.len()));
        assert!(n > 0, "the connection closed after {} bytes", got.len());
        got.extend_from_slice(&buf[..n]);
    }
    if let Some(at) = got.iter().zip(&want).position(|(a, b)| a != b) {
        panic!("the stream differs from what was sent at byte {at}");
    }
    assert_eq!(got.len(), want.len());

    drop(peer);
    runtime.shutdown();
    for handle in handles {
        handle.join().expect("worker panicked").expect("worker");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
