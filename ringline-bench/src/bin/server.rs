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

    /// (ringline only) Echo via the multi-buffer zero-copy recv-forward path
    /// (`enable_recv_forward` + `forward_held`): held provided recv buffers are
    /// scatter-gathered into one `sendmsg` with no accumulator copy.
    #[arg(long, default_value_t = false)]
    recv_forward: bool,

    /// (ringline only) Connections assigned to each worker before moving to the next.
    /// 1 = classic round-robin. Higher values pack connections onto fewer workers
    /// at low connection counts, keeping per-worker CQE density high for batching.
    #[arg(long, default_value_t = 1)]
    conn_chunk_size: usize,

    /// Restrict the whole process to these logical CPUs, e.g. `0-7,16-23` or
    /// `12,13,14,15` (the "taskset the task" model). When set, the process
    /// affinity mask is applied before launch and ringline's per-worker core
    /// pinning is disabled (so it doesn't pin to cores outside the mask).
    /// Pass `--workers N` to match the number of physical cores in the list.
    #[arg(long)]
    cpu_list: Option<String>,
}

/// Parse a cpu-list spec (`0-7,16-23` / `12,13,14,15`) into logical CPU ids.
fn parse_cpu_list(spec: &str) -> Vec<usize> {
    let mut cpus = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((lo, hi)) = part.split_once('-') {
            let lo: usize = lo.trim().parse().expect("invalid cpu-list range start");
            let hi: usize = hi.trim().parse().expect("invalid cpu-list range end");
            cpus.extend(lo..=hi);
        } else {
            cpus.push(part.parse().expect("invalid cpu-list entry"));
        }
    }
    cpus
}

/// Pin the current process to `cpus` via `sched_setaffinity` (taskset-equivalent,
/// in-process). Worker threads spawned afterwards inherit this mask.
#[cfg(target_os = "linux")]
fn apply_cpu_affinity(cpus: &[usize]) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        for &c in cpus {
            libc::CPU_SET(c, &mut set);
        }
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if ret != 0 {
            panic!(
                "sched_setaffinity({cpus:?}) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Process CPU affinity is not supported on this platform (no-op).
#[cfg(not(target_os = "linux"))]
fn apply_cpu_affinity(_cpus: &[usize]) {
    eprintln!("bench-server: --cpu-list ignored (CPU affinity unsupported on this platform)");
}

fn main() {
    let args = Args::parse();

    // Apply process CPU affinity before launch so worker threads inherit it.
    // Disables ringline's own per-worker pinning (see run_ringline) to avoid
    // pinning workers to cores outside the requested mask.
    let pin_to_core = match &args.cpu_list {
        Some(spec) => {
            let cpus = parse_cpu_list(spec);
            assert!(!cpus.is_empty(), "--cpu-list parsed to an empty set");
            apply_cpu_affinity(&cpus);
            eprintln!("bench-server: pinned process to CPUs {cpus:?}");
            false
        }
        None => true,
    };

    let workers = if args.workers == 0 {
        ringline::physical_core_count()
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
        Runtime::Ringline => run_ringline(
            args.addr,
            workers,
            args.msg_size,
            args.recv_forward,
            args.conn_chunk_size,
            pin_to_core,
        ),
        Runtime::Tokio => run_tokio(args.addr, workers, args.msg_size),
    }
}

#[allow(clippy::manual_async_fn)]
fn run_ringline(
    addr: SocketAddr,
    workers: usize,
    msg_size: usize,
    recv_forward: bool,
    conn_chunk_size: usize,
    pin_to_core: bool,
) {
    use ringline::{AsyncEventHandler, Config, ConnCtx, RinglineBuilder};
    // ParseResult is only needed in the non-io_uring fallback path.
    #[cfg(not(has_io_uring))]
    use ringline::ParseResult;

    // Direct-echo path (default): no task wakeup per message — echo SQEs are
    // submitted directly from handle_recv_multi, bypassing collect_wakeups and
    // poll_ready_tasks entirely. Falls back to the forward_recv_buf loop on the
    // mio backend (macOS / non-io_uring builds).
    struct EchoHandler;
    impl AsyncEventHandler for EchoHandler {
        fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
            async move {
                #[cfg(has_io_uring)]
                {
                    conn.run_direct_echo().await;
                    return;
                }
                #[cfg(not(has_io_uring))]
                loop {
                    let n = conn
                        .with_data(|data| {
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
        fn create_for_worker(_id: usize) -> Self {
            EchoHandler
        }
    }

    // Multi-buffer zero-copy recv-forward path: hold provided recv buffers and
    // scatter-gather them back in one sendmsg — no accumulator copy at all.
    struct RecvForwardEchoHandler;
    impl AsyncEventHandler for RecvForwardEchoHandler {
        fn on_accept(&self, conn: ConnCtx) -> impl std::future::Future<Output = ()> + 'static {
            async move {
                conn.enable_recv_forward();
                loop {
                    conn.recv_ready().await;
                    let n = match conn.forward_held() {
                        Ok(f) => f.await.unwrap_or(0),
                        Err(_) => break,
                    };
                    if n == 0 {
                        break;
                    }
                }
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            RecvForwardEchoHandler
        }
    }

    let mut config = Config::default();
    config.worker.threads = workers;
    // When --cpu-list set a process affinity mask, leave the OS to schedule
    // workers within it; otherwise pin each worker to its own core (0..N).
    config.worker.pin_to_core = pin_to_core;
    config.sq_entries = 256;
    config.recv_buffer.ring_size = 256;
    config.recv_buffer.buffer_size = msg_size.next_power_of_two().max(4096) as u32;
    config.max_connections = 16384;
    config.send_copy_count = 512;
    config.send_copy_slot_size = msg_size.next_power_of_two().max(4096) as u32;
    config.conn_chunk_size = conn_chunk_size;

    let builder = RinglineBuilder::new(config).bind(addr);
    let (shutdown, handles) = if recv_forward {
        builder.launch::<RecvForwardEchoHandler>()
    } else {
        builder.launch::<EchoHandler>()
    }
    .expect("failed to launch ringline server");

    eprintln!("bench-server: ready (recv_forward={recv_forward})");

    // Block until SIGINT/SIGTERM, then trigger graceful shutdown so each
    // worker's event loop runs its shutdown path — including the
    // `[ringline diag]`/`[ringline stall]` counter dump. (A SIGKILL at
    // teardown skips that, hiding the server-side loop diagnostics.)
    shutdown.wait_on_signal();

    for h in handles {
        h.join().ok();
    }
}

fn run_tokio(addr: SocketAddr, workers: usize, msg_size: usize) {
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
            let (mut stream, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => continue,
            };
            stream.set_nodelay(true).ok();

            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; msg_size];
                loop {
                    if stream.read_exact(&mut buf).await.is_err() {
                        break;
                    }
                    if stream.write_all(&buf).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
}
