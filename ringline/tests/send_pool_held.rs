#![allow(clippy::manual_async_fn)]
//! `SendHalf::send_pool_held` counts the send-pool slots a connection's sends
//! hold: all of an admitted send's slots until it completes, none after.

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

const SLOT: u32 = 16384;
const SLOTS: u16 = 64;
/// Ten slots' worth, the last one partly filled.
const LEN: usize = 9 * SLOT as usize + 100;
const NEEDED: usize = 10;

/// What the handler saw: held straight after admission, the worker's
/// `conn_held_max` then, and held after the send completed.
static SEEN: Mutex<Option<(usize, u64, usize)>> = Mutex::new(None);

struct Sender;

impl AsyncEventHandler for Sender {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            // Wait for the client's go byte. `wait_for_server`'s probe
            // connection closes without one.
            let n = conn.with_data(|d| ParseResult::Consumed(d.len())).await;
            if n == 0 {
                return;
            }
            let held_before = conn.send_pool_held();
            assert_eq!(held_before, 0);
            let data = vec![0x5au8; LEN];
            let done = conn.send_admitted(&data).await.expect("send admitted");
            // The task has not yielded since admission, so no completion has
            // been processed: every slot the send took is still held.
            let held = conn.send_pool_held();
            let max = ringline::send_admission_counters().conn_held_max;
            done.await.expect("send completed");
            let after = conn.send_pool_held();
            *SEEN.lock().unwrap() = Some((held, max, after));
            conn.close();
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Sender
    }
}

fn wait_for_server(addr: &str) {
    for _ in 0..200 {
        if TcpStream::connect(addr).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("server did not start on {addr}");
}

#[test]
fn an_admitted_send_s_slots_are_held_until_it_completes() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(256)
        .max_connections(16)
        .send_pool(SLOTS, SLOT)
        .build()
        .expect("valid config");
    let (shutdown, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Sender>()
        .expect("launch failed");
    let addr = shutdown.bound_addr().expect("bound_addr").to_string();
    wait_for_server(&addr);

    let mut stream = TcpStream::connect(&addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(b"g").unwrap();
    let mut got = Vec::new();
    stream.read_to_end(&mut got).unwrap();
    assert_eq!(got.len(), LEN);

    let seen = SEEN.lock().unwrap().take().expect("handler finished");
    assert_eq!(seen.0, NEEDED, "held straight after admission");
    assert!(
        seen.1 >= NEEDED as u64,
        "conn_held_max {} below the held count",
        seen.1
    );
    assert_eq!(seen.2, 0, "held after the send completed");

    shutdown.shutdown();
    common::join_workers(&shutdown, handles);
}
