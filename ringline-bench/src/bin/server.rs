//! Standalone echo server for distributed benchmarking.
//!
//! Usage:
//!   bench-server --runtime ringline --addr 0.0.0.0:7878 --workers 4 --msg-size 64
//!   bench-server --runtime tokio --addr 0.0.0.0:7878 --workers 4

use std::net::SocketAddr;

use clap::Parser;

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Runtime {
    Ringline,
    Tokio,
}

#[derive(Parser)]
#[command(
    name = "bench-server",
    about = "Echo server for distributed benchmarking"
)]
struct Args {
    /// Server runtime
    #[arg(long)]
    runtime: Runtime,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0:7878")]
    addr: SocketAddr,

    /// Number of worker threads (0 = available parallelism)
    #[arg(long, default_value_t = 0)]
    workers: usize,

    /// Message size hint for buffer tuning (bytes)
    #[arg(long, default_value_t = 4096)]
    msg_size: usize,
}

fn main() {
    let args = Args::parse();

    let workers = if args.workers == 0 {
        std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1)
    } else {
        args.workers
    };

    let runtime_name = match args.runtime {
        Runtime::Ringline => "ringline",
        Runtime::Tokio => "tokio",
    };

    eprintln!(
        "bench-server: {} runtime, {} workers, listening on {}",
        runtime_name, workers, args.addr,
    );

    match args.runtime {
        Runtime::Ringline => run_ringline(args.addr, workers, args.msg_size),
        Runtime::Tokio => run_tokio(args.addr, workers),
    }
}

#[allow(clippy::manual_async_fn)]
fn run_ringline(addr: SocketAddr, workers: usize, msg_size: usize) {
    use ringline::{AsyncEventHandler, Config, ConnCtx, ParseResult, RinglineBuilder};

    struct EchoHandler;

    impl AsyncEventHandler for EchoHandler {
        fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
            async move {
                loop {
                    let n = conn
                        .with_data(|data| {
                            let _ = conn.forward_recv_buf(data);
                            ParseResult::Consumed(data.len())
                        })
                        .await;
                    if n == 0 {
                        break;
                    }
                }
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            EchoHandler
        }
    }

    let mut config = Config::default();
    config.worker.threads = workers;
    config.worker.pin_to_core = true;
    config.sq_entries = 256;
    config.recv_buffer.ring_size = 256;
    config.recv_buffer.buffer_size = msg_size.next_power_of_two().max(4096) as u32;
    config.max_connections = 16384;
    config.send_copy_count = 512;
    config.send_copy_slot_size = msg_size.next_power_of_two().max(4096) as u32;

    let (_shutdown, handles) = RinglineBuilder::new(config)
        .bind(addr)
        .launch::<EchoHandler>()
        .expect("failed to launch ringline server");

    eprintln!("bench-server: ready");

    for h in handles {
        h.join().ok();
    }
}

fn run_tokio(addr: SocketAddr, workers: usize) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(async move {
        let socket = tokio::net::TcpSocket::new_v4().expect("failed to create socket");
        socket.set_reuseaddr(true).expect("failed to set reuseaddr");
        socket.bind(addr).expect("failed to bind");
        let listener = socket.listen(1024).expect("failed to listen");

        eprintln!("bench-server: ready");

        loop {
            let (stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            stream.set_nodelay(true).ok();

            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.into_split();
                tokio::io::copy(&mut rd, &mut wr).await.ok();
            });
        }
    });
}
