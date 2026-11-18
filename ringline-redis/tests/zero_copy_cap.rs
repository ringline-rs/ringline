//! A client whose connection is at ringline's `zero_copy_hold_cap` still
//! sends its guarded requests: `flush` copies a guarded batch that ringline
//! would refuse.
//!
//! Linux only: on mio a guard is copied and takes no send slab entry.
#![cfg(target_os = "linux")]

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::fd::AsRawFd;
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, RegionId, RinglineBuilder, SendGuard,
};
use ringline_redis::{Client, CompletedOp};

/// Above the client's default `zc_threshold` (4096), so each guarded SET is
/// a zero-copy batch, and more than the stub's receive buffer takes, so a
/// batch's last bytes stay unacknowledged while the stub does not read.
const VALUE_LEN: usize = 1 << 20;
/// Guarded SETs fired, each flushed alone.
const SETS: u64 = 10;

struct VecGuard(Vec<u8>);

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.0.as_ptr(), self.0.len() as u32)
    }
    fn region(&self) -> RegionId {
        RegionId::UNREGISTERED
    }
}

static SERVER_ADDR: OnceLock<SocketAddr> = OnceLock::new();
static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
/// Set once every SET is flushed; the stub reads only after it.
static FLUSHED: AtomicBool = AtomicBool::new(false);

/// Fire and flush `SETS` guarded SETs while the stub does not read, then
/// receive every reply.
async fn run(addr: SocketAddr) -> Result<(), String> {
    let conn = ringline::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    let mut client = Client::new(conn);
    for i in 0..SETS {
        client
            .fire_set_with_guard(b"k", VecGuard(vec![7u8; VALUE_LEN]), i)
            .map_err(|e| format!("fire {i}: {e}"))?;
        client.flush().map_err(|e| format!("flush {i}: {e}"))?;
    }
    FLUSHED.store(true, Ordering::SeqCst);
    for i in 0..SETS {
        match client.recv().await.map_err(|e| format!("recv {i}: {e}"))? {
            CompletedOp::Set { result, .. } => result.map_err(|e| format!("SET {i}: {e}"))?,
            _ => return Err(format!("reply {i} is not a SET")),
        }
    }
    Ok(())
}

struct ClientHandler;

impl AsyncEventHandler for ClientHandler {
    #[allow(clippy::manual_async_fn)]
    fn on_accept(&self, _conn: Connection) -> impl Future<Output = ()> + 'static {
        async {}
    }

    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        let addr = *SERVER_ADDR.get().expect("server addr not set");
        Some(Box::pin(async move {
            RESULT.set(run(addr).await).ok();
            ringline::request_shutdown().ok();
        }))
    }

    fn create_for_worker(_id: usize) -> Self {
        ClientHandler
    }
}

/// Accept one connection on `listener`, wait for `FLUSHED`, then read
/// `SETS` SETs of `k`, check each value and answer `+OK`.
fn stub(listener: TcpListener) {
    let (mut s, _) = listener.accept().expect("accept");
    while !FLUSHED.load(Ordering::SeqCst) {
        if RESULT.get().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let header = format!("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n${VALUE_LEN}\r\n");
    let mut request = vec![0u8; header.len() + VALUE_LEN + 2];
    for _ in 0..SETS {
        s.read_exact(&mut request).expect("read a SET");
        let ok = request.starts_with(header.as_bytes())
            && request[header.len()..header.len() + VALUE_LEN]
                .iter()
                .all(|&b| b == 7)
            && request.ends_with(b"\r\n");
        let reply: &[u8] = if ok { b"+OK\r\n" } else { b"-ERR bad SET\r\n" };
        s.write_all(reply).expect("reply");
    }
}

/// The client runtime's slab has four entries and `zero_copy_hold_cap` is 1.
/// The stub's receive buffer is smaller than a value and it does not read
/// until every SET is flushed, so the first zero-copy batches stay
/// unacknowledged and hold their entries; with three held the slab is over
/// half used and the connection is at the cap. The later flushes are copied,
/// and every SET is answered.
#[test]
fn guarded_sets_at_the_zero_copy_cap_are_copied() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    // With a 4 KiB buffer the test hung once the stub read, with the cap on
    // or off; 256 KiB, above loopback's MSS of about 64 KiB, does not. The
    // cause is not known.
    let rcvbuf: libc::c_int = 256 << 10;
    // SAFETY: setsockopt on a descriptor the listener owns.
    let set = unsafe {
        libc::setsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&rcvbuf as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(set, 0, "SO_RCVBUF: {}", std::io::Error::last_os_error());
    SERVER_ADDR.set(listener.local_addr().unwrap()).ok();
    let server = std::thread::spawn(move || stub(listener));

    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .max_connections(16)
        .send_slab_slots(4)
        .zero_copy_hold_cap(1)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .launch::<ClientHandler>()
        .expect("client launch failed");
    common::join_workers(&runtime, handles);
    server.join().expect("stub panicked");

    let result = RESULT.get().expect("client did not set a result");
    if let Err(e) = result {
        panic!("client failed: {e}");
    }
}
