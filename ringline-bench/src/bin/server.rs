//! Standalone echo server for distributed benchmarking.
//!
//! Usage:
//!   bench-server --runtime ringline --addr 0.0.0.0:7878 --workers 4 --msg-size 64
//!   bench-server --runtime tokio --addr 0.0.0.0:7878 --workers 4

use ringline::{ConfigBuilder, Connection};
use std::net::SocketAddr;

use clap::Parser;

/// Everything the proxy mode needs, bundled because the argument list had
/// outgrown what clippy will accept and most of it travels together anyway.
#[derive(Clone)]
struct ProxyCfg {
    addr: SocketAddr,
    workers: usize,
    msg_size: usize,
    backend: SocketAddr,
    conn_chunk_size: usize,
    pin_to_core: bool,
    prefault_buffers: bool,
    api: ProxyApi,
    metrics_out: Option<std::path::PathBuf>,
}

/// A self-signed server config for the connect-rate arm.
///
/// Generated per process: the connect-rate benchmark is about handshake cost,
/// not about key management, and generating here keeps cert material out of
/// the repo and off the guests.
fn self_signed_server_config() -> ringline::TlsConfig {
    use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed cert");
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let chain = vec![CertificateDer::from(cert.cert)];
    ringline::TlsConfig::builder()
        .cert(chain, key.into())
        .build()
        .expect("valid server config")
}

/// Everything the echo arm needs. A struct for the same reason `ProxyCfg` is
/// one: the argument list had outgrown what clippy accepts, and these travel
/// together anyway.
#[derive(Clone)]
struct EchoCfg {
    addr: SocketAddr,
    workers: usize,
    msg_size: usize,
    metrics_out: Option<std::path::PathBuf>,
    echo_mode: EchoMode,
    conn_chunk_size: usize,
    pin_to_core: bool,
    prefault_buffers: bool,
    defer_recv_arm: bool,
    iowq_max_workers: Option<u32>,
    accept_mode: AcceptModeArg,
    /// Offer every connection for park after each response.
    park: bool,
    /// Steer the upper half of workers out, then back in after this long.
    park_imbalance_ms: u64,
    /// Terminate TLS on the listener, with a self-signed certificate generated
    /// at startup so nothing has to be staged onto a guest.
    tls: bool,
    /// Event-loop tick interval, microseconds.
    tick_timeout_us: u64,
    /// Simulated per-request application work, microseconds.
    service_time_us: u64,
}

/// Simulated per-request application work, nanoseconds. Same reason as
/// `PARK_ENABLED` for being a static: handlers are unit structs.
static SERVICE_NS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Request size, so a recv buffer carrying several pipelined requests can be
/// charged for each of them rather than once for the buffer.
static SERVICE_MSG_SIZE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Burn `ns` nanoseconds of CPU.
///
/// A busy spin and deliberately **not** a sleep: the point is to model
/// application work that occupies the core, and sleeping would yield it and
/// let the worker serve other connections — which is the opposite of what
/// CPU-bound request handling does, and would make the knob measure nothing.
///
/// `Instant::now()` costs ~20-25 ns, so this cannot resolve much below ~50 ns;
/// the flag documents that floor. The clock read is also what stops the loop
/// being optimised away.
#[inline]
fn burn_ns(ns: u64) {
    if ns == 0 {
        return;
    }
    let start = std::time::Instant::now();
    while (start.elapsed().as_nanos() as u64) < ns {
        std::hint::spin_loop();
    }
}

/// Charge simulated work for every request in `data`.
///
/// A recv buffer under load carries several pipelined requests — that is the
/// whole coalescing effect this harness exists to measure — so charging once
/// per `with_data` call would bill per *buffer* and make simulated work get
/// cheaper the more the runtime batches. Exactly backwards. Charge per
/// `msg_size` chunk instead.
#[inline]
fn burn_for(data_len: usize) {
    let ns = SERVICE_NS.load(std::sync::atomic::Ordering::Relaxed);
    if ns == 0 {
        return;
    }
    let msg = SERVICE_MSG_SIZE
        .load(std::sync::atomic::Ordering::Relaxed)
        .max(1);
    let requests = (data_len as u64 / msg).max(1);
    burn_ns(ns.saturating_mul(requests));
}

/// Which accept path the echo arm runs, so a pool-vs-merged A/B does not need
/// two builds. Mirrors `ringline::AcceptMode`; `Merged` is io_uring only and is
/// ignored on a mio build.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum AcceptModeArg {
    /// One acceptor thread per listener, explicit round-robin placement.
    Pool,
    /// Each worker owns a SO_REUSEPORT listener and accepts on its own ring.
    Merged,
}

impl From<AcceptModeArg> for ringline::AcceptMode {
    fn from(a: AcceptModeArg) -> Self {
        match a {
            AcceptModeArg::Pool => ringline::AcceptMode::Pool,
            AcceptModeArg::Merged => ringline::AcceptMode::Merged,
        }
    }
}

/// Which forwarding entry point the proxy arm drives.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ProxyApi {
    /// `forward_to_conn` with a ringline connection as the sink, on both
    /// backends. On io_uring an accepted plaintext connection receives into
    /// its accumulator, and the forward sends from there.
    Conn,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum TokioScheduler {
    MultiThread,
    PerCore,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum TokioEcho {
    Copy,
    Splice,
}

/// Which ringline echo strategy `bench-server` drives.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum EchoMode {
    /// `with_data` + `send_nowait`.
    Copy,
    /// `with_data` + `forward_recv_buf`.
    Forward,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Runtime {
    Ringline,
    /// tokio on its own io_uring runtime (`tokio-uring`). Linux only, and only
    /// when built with `--features tokio-uring-arm`.
    TokioUring,
    Tokio,
}

#[derive(Parser)]
#[command(
    name = "bench-server",
    about = "Echo server for distributed benchmarking"
)]
struct Args {
    /// Server runtime
    #[arg(long, required_unless_present = "print_backend")]
    runtime: Option<Runtime>,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0:7878")]
    addr: SocketAddr,

    /// Number of worker threads (0 = available parallelism)
    #[arg(long, default_value_t = 0)]
    workers: usize,

    /// Message size hint for buffer tuning (bytes)
    #[arg(long, default_value_t = 4096)]
    msg_size: usize,

    /// (ringline only, required with `--runtime ringline` unless
    /// `--proxy-backend` is set) Which echo strategy the handler uses:
    ///
    /// - `copy`: `with_data` + `send_nowait`, which copies the received bytes
    ///   into a send.
    /// - `forward`: `with_data` + `forward_recv_buf` — the ordinary
    ///   parse-then-forward loop a protocol server would write. On io_uring
    ///   it sends the accumulator under a guard (zero-copy at or above
    ///   `send_zc_threshold`); on mio it copies.
    #[arg(long, value_enum)]
    echo_mode: Option<EchoMode>,

    /// (ringline only) Which accept path the echo arm runs. `merged` is
    /// io_uring only and is ignored on a mio build.
    #[arg(long, value_enum, default_value_t = AcceptModeArg::Pool)]
    accept_mode: AcceptModeArg,

    /// (ringline only) Offer each connection for rebalancing after every
    /// response (tier 3 park, #443).
    ///
    /// Park is opt-in, so without this nothing in the fleet ever offers and
    /// the policy cannot fire — a run without it measures park's absence, not
    /// park. The echo handler keeps no per-connection state, so it deposits
    /// nothing and lets `on_adopt` default to `on_accept`.
    #[arg(long, default_value_t = false)]
    park: bool,

    /// (ringline only) Manufacture a post-accept imbalance for park to
    /// repair, then hold it: steer the upper half of the workers out of the
    /// accept rotation at startup and back in after this many milliseconds.
    /// 0 disables.
    ///
    /// Tier 1 places arrivals onto the least loaded worker, so a healthy
    /// merged-mode fleet is balanced at accept and there is nothing for tier 3
    /// to do. Park exists for imbalance that appears *after* accept, and this
    /// is the cheapest way to produce that deterministically: connections open
    /// while half the fleet is excluded, then the excluded half is readmitted
    /// with no new arrivals to rebalance through. Without it a park
    /// measurement reads "never fired", which is indistinguishable from
    /// "broken".
    #[arg(long, default_value_t = 0)]
    park_imbalance_ms: u64,

    /// (ringline only) Terminate TLS, with a self-signed certificate
    /// generated at startup.
    #[arg(long, default_value_t = false)]
    tls: bool,

    /// (ringline only) Event-loop tick interval in microseconds. Exposed to
    /// tell a stall that is waiting for the periodic tick from one that is
    /// not: if throughput tracks this knob, the work is tick-driven.
    #[arg(long, default_value_t = 1000)]
    tick_timeout_us: u64,

    /// Simulated per-request application work in MICROSECONDS, burned as a busy
    /// spin before each response.
    ///
    /// Echo with no work is a byte pipe, so runtime overhead *is* its cost and
    /// any change to that overhead shows up at full strength. A real server pays
    /// parsing, lookup and response building on top, which dilutes it: at ~8us
    /// per completion, the whole spread-vs-concentrate difference is ~12us per
    /// request, worth 4x at 0us of work and ~1.06x at 200us. This knob makes that
    /// dilution measurable instead of arithmetic.
    ///
    /// Charged **per request**, not per recv buffer: a buffer carrying several
    /// pipelined requests is billed for each, otherwise simulated work would get
    /// cheaper the more the runtime batches.
    ///
    /// A busy spin, not a sleep — sleeping would yield the core to other
    /// connections, which CPU-bound request handling does not do. Resolution
    /// floor is ~50ns (the cost of the clock read), so values below ~1us are
    /// approximate. Needs `--echo-mode forward`.
    #[arg(long, default_value_t = 0)]
    service_time_us: u64,

    /// (tokio only) Scheduler shape. `multi-thread` is tokio's default
    /// work-stealing runtime; `per-core` gives each core its own
    /// `current_thread` runtime and `SO_REUSEPORT` listener, matching
    /// ringline's thread-per-core structure. Isolates scheduler shape from
    /// I/O interface in the comparison.
    #[arg(long, value_enum, default_value_t = TokioScheduler::MultiThread)]
    tokio_scheduler: TokioScheduler,

    /// (tokio only) How the bytes move. `copy` is the canonical echo loop
    /// (read into a reused buffer, write back out); `splice` moves them
    /// socket -> pipe -> socket without entering user memory. Linux only.
    #[arg(long, value_enum, default_value_t = TokioEcho::Copy)]
    tokio_echo: TokioEcho,

    /// (ringline) Run as a one-way proxy to this backend instead of echoing:
    /// every accepted connection is forwarded to a fresh connection to
    /// `--proxy-backend` with `forward_to_conn`.
    #[arg(long)]
    proxy_backend: Option<SocketAddr>,

    /// Print which ringline backend this binary was built against and exit.
    ///
    /// The backend is a compile-time choice, so an io_uring build and a mio
    /// build are two different binaries that look identical from the outside.
    /// An A/B harness that builds both must verify it got both — a build that
    /// fails and leaves the previous binary in place otherwise measures the
    /// same arm twice and reports a dead heat.
    #[arg(long)]
    print_backend: bool,

    /// (ringline) Write ringline's runtime counters to this path as JSON when
    /// the server shuts down, and print the interesting ones to stderr.
    ///
    /// Counters such as `send_eagain`, `send_exhausted` and
    /// `recv_arm_failures` say why an arm was slower, which a throughput
    /// number alone cannot.
    #[arg(long)]
    metrics_out: Option<std::path::PathBuf>,

    /// (ringline, `--proxy-backend` only) Which forwarding API the proxy uses.
    /// `conn` (`forward_to_conn`) is the only one.
    #[arg(long, value_enum, default_value_t = ProxyApi::Conn)]
    proxy_api: ProxyApi,

    /// (ringline only) Connections assigned to each worker before moving to the next.
    /// 1 = classic round-robin. Higher values pack connections onto fewer workers
    /// at low connection counts, keeping per-worker CQE density high for batching.
    #[arg(long, default_value_t = 1)]
    conn_chunk_size: usize,

    /// (ringline) Touch every send-pool page at startup so the minor faults
    /// are paid before traffic instead of on the send path
    /// (`ConfigBuilder::prefault_buffers`).
    #[arg(long, default_value_t = false)]
    prefault_buffers: bool,

    /// (ringline echo) Arm a parked reader's receive after the worker's next
    /// wait (`ConfigBuilder::defer_recv_arm`).
    #[arg(long, default_value_t = false)]
    defer_recv_arm: bool,

    /// (ringline echo) Cap each worker's bounded io-wq pool
    /// (`ConfigBuilder::iowq_max_workers`; 0 leaves the kernel default).
    /// Omitted, ringline's default applies. The knob under measurement in
    /// #584.
    #[arg(long)]
    iowq_max_workers: Option<u32>,

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

/// Print ringline's runtime counters, and write them to `path` if one was
/// given. Called after the shutdown signal so the numbers cover the whole run.
fn dump_runtime_metrics(path: Option<&std::path::Path>) {
    ringline_bench::runtime_metrics::print_summary();
    if let Some(path) = path {
        match ringline_bench::runtime_metrics::dump_to(path) {
            Ok(()) => eprintln!("bench-server: wrote runtime metrics to {}", path.display()),
            // Loud: an arm whose counters did not land cannot be explained
            // later, and a silently missing file looks like a healthy run.
            Err(e) => eprintln!(
                "bench-server: FAILED to write runtime metrics to {}: {e}",
                path.display()
            ),
        }
    }
}

/// The backend this binary was compiled against, as a word.
const RINGLINE_BACKEND: &str = if cfg!(has_io_uring) {
    "io_uring"
} else {
    "mio"
};

fn main() {
    let args = Args::parse();

    if args.print_backend {
        println!("{RINGLINE_BACKEND}");
        return;
    }

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

    // `--print-backend` is the only path that may omit it, and that returned
    // above.
    let runtime = args.runtime.expect("--runtime is required");
    let runtime_name = match runtime {
        Runtime::Ringline => "ringline",
        Runtime::Tokio => "tokio",
        Runtime::TokioUring => "tokio-uring",
    };

    eprintln!(
        "bench-server: {} runtime, {} workers, listening on {}",
        runtime_name, workers, args.addr,
    );

    match runtime {
        Runtime::Ringline if args.proxy_backend.is_some() => run_ringline_proxy(ProxyCfg {
            addr: args.addr,
            workers,
            msg_size: args.msg_size,
            backend: args.proxy_backend.expect("checked"),
            conn_chunk_size: args.conn_chunk_size,
            pin_to_core,
            prefault_buffers: args.prefault_buffers,
            api: args.proxy_api,
            metrics_out: args.metrics_out.clone(),
        }),
        Runtime::Ringline => run_ringline(EchoCfg {
            addr: args.addr,
            workers,
            msg_size: args.msg_size,
            metrics_out: args.metrics_out.clone(),
            prefault_buffers: args.prefault_buffers,
            defer_recv_arm: args.defer_recv_arm,
            iowq_max_workers: args.iowq_max_workers,
            echo_mode: args.echo_mode.unwrap_or_else(|| {
                // No default: a spec must name the loop it measures.
                eprintln!("bench-server: --runtime ringline needs --echo-mode copy or forward");
                std::process::exit(2);
            }),
            conn_chunk_size: args.conn_chunk_size,
            pin_to_core,
            accept_mode: args.accept_mode,
            park: args.park,
            park_imbalance_ms: args.park_imbalance_ms,
            tls: args.tls,
            tick_timeout_us: args.tick_timeout_us,
            service_time_us: args.service_time_us,
        }),
        Runtime::Tokio => {
            use ringline_bench::servers::tokio_arms;
            tokio_arms::run(
                args.addr,
                workers,
                args.msg_size,
                match args.tokio_scheduler {
                    TokioScheduler::MultiThread => tokio_arms::TokioScheduler::MultiThread,
                    TokioScheduler::PerCore => tokio_arms::TokioScheduler::PerCore,
                },
                match args.tokio_echo {
                    TokioEcho::Copy => tokio_arms::TokioEcho::Copy,
                    TokioEcho::Splice => tokio_arms::TokioEcho::Splice,
                },
                pin_to_core,
            )
        }
        Runtime::TokioUring => run_tokio_uring(args.addr, workers, args.msg_size, pin_to_core),
    }
}

#[cfg(all(target_os = "linux", feature = "tokio-uring-arm"))]
fn run_tokio_uring(addr: SocketAddr, workers: usize, msg_size: usize, pin_to_core: bool) {
    ringline_bench::servers::tokio_uring_arm::run(addr, workers, msg_size, pin_to_core)
}

#[cfg(not(all(target_os = "linux", feature = "tokio-uring-arm")))]
fn run_tokio_uring(_addr: SocketAddr, _workers: usize, _msg_size: usize, _pin_to_core: bool) {
    eprintln!(
        "bench-server: --runtime tokio-uring needs a Linux build with \
         --features tokio-uring-arm"
    );
    std::process::exit(2);
}

/// One-way proxy: forward every accepted connection's stream to a fresh
/// connection to `backend` with `forward_to_conn`, which exists on both
/// backends.
#[allow(clippy::manual_async_fn)]
fn run_ringline_proxy(cfg: ProxyCfg) {
    let ProxyCfg {
        addr,
        workers,
        msg_size,
        backend,
        conn_chunk_size,
        pin_to_core,
        prefault_buffers,
        api,
        metrics_out,
    } = cfg;
    use ringline::{AsyncEventHandler, Connection, RinglineBuilder};

    /// Forward for the life of the connection: the caller asks for a byte
    /// count, and a proxy does not know one, so ask for more than any run will
    /// carry and let the peer's FIN end it (both APIs resolve short on FIN).
    const UNTIL_EOF: usize = usize::MAX / 2;

    static BACKEND: std::sync::OnceLock<SocketAddr> = std::sync::OnceLock::new();
    let _ = BACKEND.set(backend);

    /// `forward_to_conn` with a ringline connection as the sink — the form
    /// both backends have. The connect is the runtime's, so it costs one
    /// async round trip instead of a blocking syscall on the worker.
    struct ConnProxy;
    impl AsyncEventHandler for ConnProxy {
        fn on_accept(
            &self,
            mut conn: Connection,
        ) -> impl std::future::Future<Output = ()> + 'static {
            async move {
                let addr = *BACKEND.get().expect("backend set before launch");
                let sink = match ringline::connect(addr).await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("proxy: backend connect failed: {e}");
                        return;
                    }
                };
                // The sink is presented as its write half: holding it is the
                // permission to write, and the borrow keeps anything else from
                // sending to that socket while the forward runs.
                // A `Connection` already owns both halves, so the write half is
                // taken by splitting rather than claimed from a shared handle.
                let (mut sink_tx, _sink_rx) = sink.split();
                if let Err(e) = conn.forward_to_conn(&mut sink_tx, UNTIL_EOF).await {
                    eprintln!("proxy: forward failed: {e}");
                }
            }
        }
        fn create_for_worker(_id: usize) -> Self {
            ConnProxy
        }
    }

    let config = ConfigBuilder::new()
        .workers(workers)
        .pin_to_core(pin_to_core)
        .sq_entries(256)
        .prefault_buffers(prefault_buffers)
        .max_connections(16384)
        .send_pool(512, msg_size.next_power_of_two().max(4096) as u32)
        .conn_chunk_size(conn_chunk_size)
        .build()
        .expect("valid config");

    let builder = RinglineBuilder::new(config).bind(addr);
    let (shutdown, handles) = match api {
        ProxyApi::Conn => builder.launch::<ConnProxy>(),
    }
    .expect("failed to launch ringline proxy");
    let api_name = match api {
        ProxyApi::Conn => "forward_to_conn",
    };
    eprintln!(
        "bench-server: ready (backend={RINGLINE_BACKEND}, proxy -> {backend}, api={api_name})"
    );
    shutdown.wait_on_signal();
    dump_runtime_metrics(metrics_out.as_deref());
    for h in handles {
        h.join().ok();
    }
}

#[allow(clippy::manual_async_fn)]
fn run_ringline(cfg: EchoCfg) {
    let EchoCfg {
        addr,
        workers,
        msg_size,
        metrics_out,
        echo_mode,
        conn_chunk_size,
        pin_to_core,
        prefault_buffers,
        defer_recv_arm,
        iowq_max_workers,
        accept_mode,
        park,
        park_imbalance_ms,
        tls,
        tick_timeout_us,
        service_time_us,
    } = cfg;
    use ringline::ParseResult;
    use ringline::{AsyncEventHandler, RinglineBuilder};

    // `copy`: copy the received bytes into a send.
    struct EchoHandler;
    impl AsyncEventHandler for EchoHandler {
        fn on_accept(&self, conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
            async move { copy_echo_loop(conn).await }
        }
        fn create_for_worker(_id: usize) -> Self {
            EchoHandler
        }
    }

    /// Set from `--park`. A static rather than handler state: these handlers
    /// are unit structs constructed per worker, and a bench switch does not
    /// justify threading a field through every one of them.
    static PARK_ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// `with_data` + `send_nowait`: the bytes are copied into a send.
    async fn copy_echo_loop(conn: Connection) {
        let (mut tx, mut rx) = conn.split();
        loop {
            let n = rx
                .with_data(|data| {
                    burn_for(data.len());
                    if let Err(e) = tx.send_nowait(data) {
                        eprintln!("echo: send_nowait failed: {e}");
                        return ParseResult::NeedMore;
                    }
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n == 0 {
                break;
            }
            if PARK_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                tx.offer_for_park(None);
            }
        }
    }

    /// `with_data` + `forward_recv_buf` — what a protocol server's read loop
    /// looks like.
    async fn forward_echo_loop(conn: Connection) {
        // The send happens inside the recv closure, so the two halves have to
        // be separately borrowable.
        let (mut tx, mut rx) = conn.split();
        loop {
            let n = rx
                .with_data(|data| {
                    // Before the response: a real server parses, works, replies.
                    burn_for(data.len());
                    if let Err(e) = tx.forward_recv_buf(data) {
                        eprintln!("echo: forward_recv_buf failed: {e}");
                        return ParseResult::NeedMore;
                    }
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n == 0 {
                break;
            }
            // The response is queued: the quiescent point park is defined
            // against. If the next request's bytes are already buffered, the
            // offer is ignored; otherwise it is withdrawn when they arrive.
            // Offering after every response is therefore safe.
            if PARK_ENABLED.load(std::sync::atomic::Ordering::Relaxed) {
                tx.offer_for_park(None);
            }
        }
    }

    struct ForwardEchoHandler;
    impl AsyncEventHandler for ForwardEchoHandler {
        fn on_accept(&self, conn: Connection) -> impl std::future::Future<Output = ()> + 'static {
            async move { forward_echo_loop(conn).await }
        }
        fn create_for_worker(_id: usize) -> Self {
            ForwardEchoHandler
        }
    }

    PARK_ENABLED.store(park, std::sync::atomic::Ordering::Relaxed);
    // Simulated work is charged per request, so the handler needs the request
    // size as well as the duration.
    SERVICE_NS.store(
        service_time_us.saturating_mul(1_000),
        std::sync::atomic::Ordering::Relaxed,
    );
    SERVICE_MSG_SIZE.store(msg_size as u64, std::sync::atomic::Ordering::Relaxed);

    let staged = ConfigBuilder::new()
        .workers(workers)
        // When --cpu-list set a process affinity mask, leave the OS to schedule
        // workers within it; otherwise pin each worker to its own core (0..N).
        .pin_to_core(pin_to_core)
        .sq_entries(256)
        .prefault_buffers(prefault_buffers)
        .defer_recv_arm(defer_recv_arm)
        .max_connections(16384)
        // With --tls the slot must hold one whole TLS record (16413 bytes at
        // the default fragment size), which the unbuffered engine requires.
        .send_pool(
            512,
            msg_size
                .next_power_of_two()
                .max(if tls { 16448 } else { 4096 }) as u32,
        )
        .conn_chunk_size(conn_chunk_size)
        .accept_mode(accept_mode.into())
        .tick_timeout_us(tick_timeout_us);
    let staged = match iowq_max_workers {
        Some(n) => staged.iowq_max_workers(n),
        None => staged,
    };
    let staged = if tls {
        staged.tls(self_signed_server_config())
    } else {
        staged
    };
    let config = staged.build().expect("valid config");

    let builder = RinglineBuilder::new(config).bind(addr);
    let (shutdown, handles) = match echo_mode {
        EchoMode::Forward => builder.launch::<ForwardEchoHandler>(),
        EchoMode::Copy => builder.launch::<EchoHandler>(),
    }
    .expect("failed to launch ringline server");

    // Manufacture the imbalance park exists to repair, then stand back.
    // Steering only affects *new* accepts, so the sequence matters: exclude
    // first, let the client establish everything on the remaining half, then
    // readmit. What is left is a standing imbalance with no arrivals — which
    // tier 1 cannot touch, because tier 1 only acts at accept time.
    // `set_worker_accepting` is Linux-only, and so is park.
    #[cfg(target_os = "linux")]
    let shutdown = if park_imbalance_ms > 0 {
        let half = workers / 2;
        // `ringline::Runtime` is not `Clone`, and the readmit has to happen on a
        // timer while the main thread waits on a signal — so share it.
        let shutdown = std::sync::Arc::new(shutdown);
        for w in half..workers {
            if let Err(e) = shutdown.set_worker_accepting(w, false) {
                eprintln!("bench-server: could not steer worker {w} out: {e}");
            }
        }
        println!("park-imbalance: workers {half}..{workers} steered out");
        let readmit = std::sync::Arc::clone(&shutdown);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(park_imbalance_ms));
            for w in half..workers {
                if let Err(e) = readmit.set_worker_accepting(w, true) {
                    eprintln!("bench-server: could not steer worker {w} back in: {e}");
                }
            }
            // The marker the analysis keys on: everything before this is the
            // imbalance being built, everything after is park's chance to
            // repair it.
            println!("park-imbalance: workers {half}..{workers} readmitted");
        });
        shutdown
    } else {
        std::sync::Arc::new(shutdown)
    };
    #[cfg(not(target_os = "linux"))]
    let shutdown = {
        let _ = park_imbalance_ms;
        shutdown
    };

    let mode = match echo_mode {
        EchoMode::Copy => "copy",
        EchoMode::Forward => "forward",
    };
    eprintln!(
        "bench-server: ready (backend={RINGLINE_BACKEND}, echo_mode={mode}, service_time={service_time_us}us/req)"
    );

    // Block until SIGINT/SIGTERM, then trigger graceful shutdown so each
    // worker's event loop runs its shutdown path — including the
    // `[ringline diag]`/`[ringline stall]` counter dump. (A SIGKILL at
    // teardown skips that, hiding the server-side loop diagnostics.)
    shutdown.wait_on_signal();
    dump_runtime_metrics(metrics_out.as_deref());

    for h in handles {
        h.join().ok();
    }
}

#[cfg(test)]
mod service_time_tests {
    use super::{SERVICE_MSG_SIZE, SERVICE_NS, burn_for, burn_ns};
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    /// The shortest of `tries` timings of `f`. A thread can be preempted
    /// mid-measurement, which only adds time, so the minimum is the timing to
    /// hold to an upper bound.
    fn fastest(tries: usize, mut f: impl FnMut()) -> std::time::Duration {
        (0..tries)
            .map(|_| {
                let t = Instant::now();
                f();
                t.elapsed()
            })
            .min()
            .expect("tries > 0")
    }

    /// One test rather than several, deliberately: `SERVICE_NS` and
    /// `SERVICE_MSG_SIZE` are process-global, and the test harness runs tests in
    /// parallel threads, so separate tests touching them would race each other
    /// and flake. A single test is single-threaded by construction.
    ///
    /// Lower bounds are measured once: `burn_ns` spins until the clock says it
    /// is done, so it cannot finish early. Upper bounds take the fastest of
    /// several runs, because preemption can stretch any single one.
    #[test]
    fn simulated_work_is_charged_per_request_not_per_buffer() {
        // Zero is free, and must not consult the clock at all.
        let took = fastest(20, || burn_ns(0));
        assert!(took.as_micros() < 50, "burn_ns(0) took {took:?}");

        // A requested duration is actually burned. Generous lower bound only:
        // the spin can overshoot (scheduling, clock granularity) but must never
        // undershoot, or every arm using it would silently model less work than
        // asked for -- the failure that makes a knob look inert.
        let t = Instant::now();
        burn_ns(2_000_000);
        let took = t.elapsed();
        assert!(
            took.as_micros() >= 2_000,
            "burn_ns(2ms) returned after {took:?}"
        );

        // Disabled by default: no service time set means no spin regardless of
        // how much data arrives.
        SERVICE_NS.store(0, Ordering::Relaxed);
        SERVICE_MSG_SIZE.store(64, Ordering::Relaxed);
        let took = fastest(20, || burn_for(64 * 100));
        assert!(
            took.as_micros() < 50,
            "burn_for with SERVICE_NS=0 took {took:?}"
        );

        // The point of the whole knob: a buffer holding several pipelined
        // requests is charged for EACH. If this were per-buffer instead,
        // simulated work would get cheaper the more the runtime coalesced --
        // exactly backwards, and it would quietly cancel the effect being
        // measured.
        //
        // Checked against the requested cost rather than against a measured
        // single request, whose own timing preemption can stretch.
        SERVICE_NS.store(200_000, Ordering::Relaxed); // 200us per request
        let t = Instant::now();
        burn_for(64 * 5); // five requests in one buffer
        let five = t.elapsed();
        assert!(
            five.as_micros() >= 5 * 200,
            "five requests in one buffer took {five:?}, less than 5 x 200us; \
             charging per buffer would take 200us"
        );

        // A short buffer still costs one request rather than zero, so a partial
        // read cannot be free.
        let t = Instant::now();
        burn_for(1);
        assert!(
            t.elapsed().as_micros() >= 150,
            "a sub-request buffer should still be charged once"
        );

        SERVICE_NS.store(0, Ordering::Relaxed);
    }
}
