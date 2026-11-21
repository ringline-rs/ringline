//! Per-connection send order with a bounded send waiting
//! (`docs/send-pool-partition-design.md`, section 2). A connection whose
//! peer has stopped reading holds more than the socket buffers take, four
//! bounded sends queued behind it, and a bounded send waiting for send-pool
//! capacity. A plain send made then is refused, and the peer reads the
//! waiting send's bytes before those of a plain send made once it has been
//! admitted.

#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

mod common;

const SLOT: usize = 32768;
const SLOTS: u16 = 8;

/// Larger than the loopback socket buffers hold, and small enough to fit
/// under an 8 MiB `RLIMIT_MEMLOCK`.
#[cfg(has_io_uring)]
const GUARD_LEN: usize = 4 << 20;

/// The bytes of the fill, of the bounded sends and of the sends made after.
const FILL: u8 = 1;
const QUEUED: u8 = 3;
const WAITING: u8 = 4;
const PLAIN: u8 = 9;
const TAIL: &[u8] = b"tail";

#[cfg(has_io_uring)]
struct VecGuard(Vec<u8>);

#[cfg(has_io_uring)]
impl ringline::SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> ringline::RegionId {
        ringline::RegionId::UNREGISTERED
    }
}

/// On io_uring: a zero-copy send the peer will not take in full.
#[cfg(has_io_uring)]
fn fill(conn: &mut Connection) {
    let guard = ringline::GuardBox::new(VecGuard(vec![FILL; GUARD_LEN]));
    conn.send_parts()
        .build(|b| b.guard(guard).submit())
        .expect("guard send accepted");
}

/// On mio: 16 MiB of plain sends, which take no send-pool slot. macOS grows
/// loopback socket buffers to 4 MiB a side.
#[cfg(not(has_io_uring))]
fn fill(conn: &mut Connection) {
    for _ in 0..256 {
        conn.send(&[FILL; 1 << 16]).expect("queued");
    }
}

/// What the sending task saw.
#[derive(Debug)]
struct Seen {
    /// The refusal of the plain send made while the bounded send waited.
    refused: String,
    /// `tickets_waited` after the bounded send's first poll.
    tickets_waited: u64,
}

static SEEN: Mutex<Option<Seen>> = Mutex::new(None);

fn kind(result: io::Result<impl Sized>) -> String {
    match result {
        Ok(_) => "Ok".to_string(),
        Err(e) => format!("{:?}: {e}", e.kind()),
    }
}

struct Sender;

impl AsyncEventHandler for Sender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // The client's go byte. `wait_for_server`'s probe closes without
            // one.
            if conn.with_data(|d| ParseResult::Consumed(d.len())).await == 0 {
                return;
            }
            static QUEUED_BYTES: [u8; SLOT] = [QUEUED; SLOT];
            static WAITING_BYTES: [u8; 6 * SLOT] = [WAITING; 6 * SLOT];
            fill(&mut conn);
            let mut queued = Vec::new();
            for _ in 0..4 {
                queued.push(conn.send_admitted(&QUEUED_BYTES).await.expect("admitted"));
            }
            let mut waiting = std::pin::pin!(conn.send_admitted(&WAITING_BYTES));
            let first =
                std::future::poll_fn(|cx| std::task::Poll::Ready(waiting.as_mut().poll(cx))).await;
            assert!(first.is_pending(), "the send waits for capacity");
            let tickets_waited = ringline::send_admission_counters().tickets_waited;
            let refused = kind(conn.send(&[PLAIN; 100]));
            *SEEN.lock().unwrap() = Some(Seen {
                refused,
                tickets_waited,
            });
            let admitted = waiting.await.expect("admitted once the peer reads");
            conn.send(TAIL).expect("nothing waits now");
            for send in queued {
                send.await.expect("sent");
            }
            admitted.await.expect("sent");
            conn.close();
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Sender
    }
}

fn wait_for_server(addr: std::net::SocketAddr) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

/// A plain send made while a bounded send waits on its connection is refused
/// with `Other`, and once the waiting send is admitted, a plain send goes out
/// after it: the peer reads the fill, the queued sends, the waiting send and
/// then the plain send, and never the refused one.
#[test]
fn a_plain_send_waits_its_turn_behind_a_waiting_bounded_send() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(SLOTS, SLOT as u32)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Sender>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound");
    wait_for_server(addr);

    let mut peer = TcpStream::connect(addr).expect("connect");
    peer.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    peer.write_all(b"g").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let seen = loop {
        if let Some(seen) = SEEN.lock().unwrap().take() {
            break seen;
        }
        assert!(Instant::now() < deadline, "the sending task never waited");
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(
        seen.refused, "Other: a bounded send waits on this connection",
        "the plain send made while the bounded send waited"
    );
    assert_eq!(seen.tickets_waited, 1);

    let mut body = Vec::new();
    peer.read_to_end(&mut body).expect("read to the close");
    assert!(
        !body.contains(&PLAIN),
        "the refused send's bytes reached the peer"
    );
    assert!(body.ends_with(TAIL), "the plain send came last");
    let rest = &body[..body.len() - TAIL.len()];
    let waiting = &rest[rest.len() - 6 * SLOT..];
    assert!(
        waiting.iter().all(|&b| b == WAITING),
        "the waiting send's bytes come just before the plain send"
    );
    let rest = &rest[..rest.len() - 6 * SLOT];
    let queued = &rest[rest.len() - 4 * SLOT..];
    assert!(queued.iter().all(|&b| b == QUEUED));
    assert!(rest[..rest.len() - 4 * SLOT].iter().all(|&b| b == FILL));

    runtime.shutdown();
    common::join_workers(&runtime, handles);
}
