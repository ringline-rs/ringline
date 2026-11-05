//! A zero-copy chain part larger than the socket's send buffer. Without
//! `MSG_WAITALL` the kernel sends what fits and reports success, and the next
//! part follows the gap (#734).

#![cfg(has_io_uring)]
#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard,
};

const GUARD_LEN: usize = 3 << 20;
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

/// Waits for one byte, then sends a chain of a large guard and a copied tail.
struct ChainSender;

impl AsyncEventHandler for ChainSender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            conn.with_data(|data| ParseResult::Consumed(data.len()))
                .await;
            let guard = GuardBox::new(VecGuard(vec![7; GUARD_LEN]));
            let sent = conn
                .send_chain(|c| c.parts().guard(guard).add().copy(TAIL).finish())
                .expect("chain accepted")
                .await;
            if sent.is_ok() {
                while conn
                    .with_data(|data| ParseResult::Consumed(data.len()))
                    .await
                    > 0
                {}
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        ChainSender
    }
}

/// The peer sees a prefix of the stream: all of it, or, if the chain failed
/// under `RLIMIT_MEMLOCK`, part of it and then a close. Never the tail after a
/// gap.
#[test]
fn a_chain_part_larger_than_the_send_buffer_leaves_no_gap() {
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
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound")).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(b"x").unwrap();
    // Not reading fills the socket buffers before the chain's send finishes.
    std::thread::sleep(Duration::from_millis(100));

    let total = GUARD_LEN + TAIL.len();
    let mut received = Vec::with_capacity(total);
    let mut buf = [0u8; 65536];
    while received.len() < total {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::ConnectionReset => break,
            Err(e) => panic!("read after {} bytes: {e}", received.len()),
        }
    }
    let guard_part = received.len().min(GUARD_LEN);
    assert!(
        received[..guard_part].iter().all(|&b| b == 7),
        "the tail arrived {} bytes into the guard",
        received[..guard_part].iter().position(|&b| b != 7).unwrap()
    );
    if received.len() > GUARD_LEN {
        assert_eq!(&received[GUARD_LEN..], TAIL);
    }

    runtime.shutdown();
    for handle in handles {
        handle.join().expect("worker panicked").expect("worker");
    }
}
