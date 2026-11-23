//! A failed send closes the connection, but bytes the peer sent before it
//! reset reach the reader before the send's error.
//!
//! On io_uring a receive is armed only when a read parks, so the peer's last
//! bytes can still be queued in the socket when a send fails. The send
//! failure reads the socket before it ends the read half.
//!
//! io_uring only: on mio the reset is read as soon as it arrives, which
//! closes the connection and drops the handler's task before it sends.

#![cfg(all(target_os = "linux", has_io_uring))]
#![allow(clippy::manual_async_fn)]

mod common;

use std::future::Future;
use std::io::Write;
use std::net::TcpStream;
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, Config, ConfigBuilder, Connection, ParseResult, RinglineBuilder,
};

/// What the handler saw: the send's result, then each read's result and the
/// lengths its closure was given.
static OUTCOME: Mutex<Option<Vec<String>>> = Mutex::new(None);

fn test_config() -> Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .build()
        .expect("valid config")
}

/// Waits for the peer's message and reset, sends, then reads.
struct SendThenRead;

impl AsyncEventHandler for SendThenRead {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut log = Vec::new();
            // The client writes 4 bytes and resets within this sleep.
            ringline::sleep(Duration::from_millis(300)).await;
            let sent = match conn.send(b"reply") {
                Ok(done) => done.await,
                Err(e) => Err(e),
            };
            log.push(match sent {
                Ok(n) => format!("send Ok({n})"),
                Err(e) => format!("send {:?}", e.kind()),
            });
            for _ in 0..4 {
                let mut seen = Vec::new();
                let read = conn
                    .with_data_result(|data| {
                        seen.push(data.len());
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                let done = !matches!(read, Ok(n) if n > 0);
                log.push(match read {
                    Ok(n) => format!("read Ok({n}) saw {seen:?}"),
                    Err(e) => format!("read {:?} saw {seen:?}", e.kind()),
                });
                if done {
                    break;
                }
            }
            *OUTCOME.lock().unwrap() = Some(log);
            ringline::request_shutdown().ok();
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        SendThenRead
    }
}

/// Write `msg`, then close with `SO_LINGER {on, 0}`, which sends an RST.
fn write_and_reset(mut client: TcpStream, msg: &[u8]) {
    client.write_all(msg).unwrap();
    let linger = libc::linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SAFETY: a valid socket and a `linger` of the size passed.
    let rc = unsafe {
        libc::setsockopt(
            client.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_LINGER,
            (&linger as *const libc::linger).cast(),
            std::mem::size_of::<libc::linger>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "SO_LINGER");
    drop(client);
}

#[test]
fn a_failed_send_delivers_the_peers_last_bytes_before_its_error() {
    let (runtime, handles) = RinglineBuilder::new(test_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<SendThenRead>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound address");
    let client = TcpStream::connect(addr).expect("connect");
    std::thread::sleep(Duration::from_millis(50));
    write_and_reset(client, b"ping");

    let deadline = Instant::now() + Duration::from_secs(20);
    let log = loop {
        if let Some(log) = OUTCOME.lock().unwrap().take() {
            break log;
        }
        assert!(Instant::now() < deadline, "the handler never finished");
        std::thread::sleep(Duration::from_millis(5));
    };
    common::join_workers(&runtime, handles);

    assert!(
        log[0].starts_with("send ") && !log[0].starts_with("send Ok"),
        "{log:?}"
    );
    assert_eq!(
        log[1], "read Ok(4) saw [4]",
        "the peer's bytes come first: {log:?}"
    );
    assert!(
        log[2].starts_with("read ConnectionReset") || log[2].starts_with("read BrokenPipe"),
        "then the send's error: {log:?}"
    );
}
