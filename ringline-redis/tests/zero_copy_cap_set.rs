//! `set_with_guard` on a connection at ringline's `zero_copy_hold_cap` sends
//! its value as a copy.
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
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, RegionId, RinglineBuilder, SendGuard,
};
use ringline_redis::Client;

/// Bytes of each raw guarded send that holds a slab entry: more than the
/// stub's receive buffer takes, so its last bytes stay unacknowledged.
const FILL_LEN: usize = 1 << 20;
/// Raw guarded sends before the SET: three of the four slab entries.
const FILLS: usize = 3;
/// The SET's value: above the client's `zc_threshold` (4096).
const VALUE_LEN: usize = 64 << 10;

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
/// Set just before the SET; the stub reads only after it.
static GO: AtomicBool = AtomicBool::new(false);

/// Hold three slab entries with raw guarded sends the stub does not read
/// yet, then send a guarded SET through the client.
async fn run(addr: SocketAddr) -> Result<(), String> {
    let mut conn = ringline::connect(addr)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    for i in 0..FILLS {
        conn.send_parts()
            .build(|b| {
                b.guard(GuardBox::new(VecGuard(vec![0u8; FILL_LEN])))
                    .submit()
            })
            .map_err(|e| format!("fill {i}: {e}"))?;
    }
    if !conn.zero_copy_capped() {
        return Err("the connection is not at the cap after the fills".into());
    }
    let mut client = Client::new(conn);
    // No task yields between here and the SET's capped check, so the worker
    // cannot release the held entries first.
    GO.store(true, Ordering::SeqCst);
    client
        .set_with_guard(b"k", VecGuard(vec![7u8; VALUE_LEN]))
        .await
        .map_err(|e| format!("set_with_guard: {e}"))
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

/// Accept one connection, wait for `GO`, discard the fills, then read one
/// SET of `k`, check its value and answer `+OK`.
fn stub(listener: TcpListener) {
    let (mut s, _) = listener.accept().expect("accept");
    while !GO.load(Ordering::SeqCst) {
        if RESULT.get().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut fill = vec![0u8; FILLS * FILL_LEN];
    s.read_exact(&mut fill).expect("read the fills");
    let header = format!("*3\r\n$3\r\nSET\r\n$1\r\nk\r\n${VALUE_LEN}\r\n");
    let mut request = vec![0u8; header.len() + VALUE_LEN + 2];
    s.read_exact(&mut request).expect("read the SET");
    let ok = request.starts_with(header.as_bytes())
        && request[header.len()..header.len() + VALUE_LEN]
            .iter()
            .all(|&b| b == 7)
        && request.ends_with(b"\r\n");
    let reply: &[u8] = if ok { b"+OK\r\n" } else { b"-ERR bad SET\r\n" };
    s.write_all(reply).expect("reply");
}

/// The client runtime's slab has four entries and `zero_copy_hold_cap` is 1.
/// Three raw guarded sends the stub does not read hold three entries, so the
/// slab is over half used and the connection is at the cap. `set_with_guard`
/// copies its value, and the SET is answered.
#[test]
fn set_with_guard_at_the_zero_copy_cap_is_copied() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    // As in `zero_copy_cap.rs`: a buffer above loopback's MSS.
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
