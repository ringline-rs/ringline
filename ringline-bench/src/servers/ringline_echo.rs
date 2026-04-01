#![allow(clippy::manual_async_fn)]

use std::net::SocketAddr;
use std::thread::JoinHandle;

use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder, ShutdownHandle};

struct EchoHandler;

impl AsyncEventHandler for EchoHandler {
    fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
        async move {
            loop {
                let n = conn
                    .with_data(|data| {
                        // Zero-copy forward: sends directly from the recv buffer
                        // when available, avoiding the SendCopyPool copy.
                        if let Err(e) = conn.forward_recv_buf(data) {
                            eprintln!("echo: forward_recv_buf failed: {e}");
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
    shutdown: ShutdownHandle,
    handles: Vec<JoinHandle<Result<(), ringline::Error>>>,
}

impl RinglineServer {
    pub fn start(
        addr: SocketAddr,
        workers: usize,
        msg_size: usize,
    ) -> Result<Self, ringline::Error> {
        let mut config = Config::default();
        config.worker.threads = workers;
        config.worker.pin_to_core = false;
        config.sq_entries = 256;
        config.recv_buffer.ring_size = 256;
        config.recv_buffer.buffer_size = msg_size.next_power_of_two().max(4096) as u32;
        config.max_connections = 4096;
        config.send_copy_count = 512;
        config.send_copy_slot_size = msg_size.next_power_of_two().max(4096) as u32;

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
