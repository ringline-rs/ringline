#![allow(clippy::manual_async_fn)]
//! A burst of connections larger than every worker's accept queue is served in
//! full: the acceptor waits for room, and the rest wait in the listen queue
//! (#658).

mod common;

use std::future::Future;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::time::Duration;

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

const CONNECTIONS: usize = 100;

/// Echoes one read, after blocking its worker for long enough that every
/// connection of the burst reaches the acceptor while nothing drains the queue.
struct BusyEcho;

impl AsyncEventHandler for BusyEcho {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut received = Vec::new();
            conn.with_data(|data| {
                received.extend_from_slice(data);
                ParseResult::Consumed(data.len())
            })
            .await;
            let _ = conn.send_nowait(&received);
        }
    }
    fn on_start(&self) -> Option<Pin<Box<dyn Future<Output = ()> + 'static>>> {
        Some(Box::pin(async {
            std::thread::sleep(Duration::from_millis(300));
        }))
    }
    fn create_for_worker(_id: usize) -> Self {
        BusyEcho
    }
}

#[test]
fn a_burst_larger_than_the_accept_queue_is_served_in_full() {
    let config = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(1024)
        .max_connections(1024)
        .accept_queue_capacity(1)
        .resolver_threads(0)
        .build()
        .expect("valid config");
    let (runtime, handles) = RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<BusyEcho>()
        .expect("launch");
    let addr = runtime.bound_addr().expect("bound");

    let mut clients: Vec<TcpStream> = (0..CONNECTIONS)
        .map(|_| {
            let mut client = TcpStream::connect(addr).expect("connect");
            client.write_all(b"ping").expect("write");
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .expect("read timeout");
            client
        })
        .collect();
    for (i, client) in clients.iter_mut().enumerate() {
        let mut reply = [0u8; 4];
        client
            .read_exact(&mut reply)
            .unwrap_or_else(|e| panic!("connection {i} of {CONNECTIONS} was not served: {e}"));
        assert_eq!(&reply, b"ping");
    }

    runtime.shutdown();
    common::join_workers(&runtime, handles);
}
