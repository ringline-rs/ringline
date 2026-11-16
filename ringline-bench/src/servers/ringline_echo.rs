#![allow(clippy::manual_async_fn)]

use std::net::SocketAddr;
use std::thread::JoinHandle;

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder, Runtime,
};

struct EchoHandler;

impl AsyncEventHandler for EchoHandler {
    fn on_accept(&self, conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            // Copy each read into a send.
            let (mut tx, mut rx) = conn.split();
            loop {
                let n = rx
                    .with_data(|data| {
                        if let Err(e) = tx.send(data) {
                            eprintln!("echo: send failed: {e}");
                            return ParseResult::NeedMore;
                        }
                        ParseResult::Consumed(data.len())
                    })
                    .await;
                if n == 0 {
                    break;
                }
            }
        }
    }

    fn create_for_worker(_worker_id: usize) -> Self {
        EchoHandler
    }
}

pub struct RinglineServer {
    shutdown: Runtime,
    handles: Vec<JoinHandle<Result<(), ringline::Error>>>,
}

impl RinglineServer {
    pub fn start(
        addr: SocketAddr,
        workers: usize,
        msg_size: usize,
    ) -> Result<Self, ringline::Error> {
        let config = ConfigBuilder::new()
            .workers(workers)
            .pin_to_core(false)
            .sq_entries(4096)
            .max_connections(4096)
            .send_pool(4096, msg_size.next_power_of_two().max(4096) as u32)
            .build()
            .expect("valid config");

        let (shutdown, handles) = RinglineBuilder::new(config)
            .bind(addr)
            .launch::<EchoHandler>()?;

        Ok(RinglineServer { shutdown, handles })
    }

    pub fn stop(self) {
        self.shutdown.shutdown();
        for h in self.handles {
            h.join().ok();
        }
    }
}
