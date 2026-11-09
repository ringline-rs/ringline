//! A connection closed on io_uring sends its FIN even while other
//! connections' requests are in flight (#581): when its task reads the peer's
//! FIN and returns, and when its task ends on its own. A peer's FIN alone
//! closes nothing (`docs/half-close-design.md`).

#![allow(clippy::manual_async_fn)]

use std::future::Future;
use std::io::Read;
use std::net::{Shutdown, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ringline::{AsyncEventHandler, ConfigBuilder, Connection, ParseResult, RinglineBuilder};

/// The tests share `ACCEPTED`, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());
static ACCEPTED: AtomicUsize = AtomicUsize::new(0);

/// Wait until the server has accepted `n` connections, so each has a recv
/// armed before the test closes one.
fn wait_accepted(n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while ACCEPTED.load(Ordering::SeqCst) < n {
        assert!(
            Instant::now() < deadline,
            "the server never accepted {n} connections"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Each connection's task reads until the peer's FIN and returns, which
/// closes the connection.
struct ReadsToEof;

impl AsyncEventHandler for ReadsToEof {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        ACCEPTED.fetch_add(1, Ordering::SeqCst);
        async move { while conn.with_data(|d| ParseResult::Consumed(d.len())).await > 0 {} }
    }
    fn create_for_worker(_id: usize) -> Self {
        ReadsToEof
    }
}

/// Each connection's task sleeps far longer than the test runs and never
/// reads.
struct Sleeps;

impl AsyncEventHandler for Sleeps {
    fn on_accept(&self, conn: Connection) -> impl Future<Output = ()> + 'static {
        ACCEPTED.fetch_add(1, Ordering::SeqCst);
        async move {
            let _conn = conn;
            ringline::sleep(Duration::from_secs(60)).await;
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        Sleeps
    }
}

fn config() -> ringline::Config {
    ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(16, 16384)
        .blocking_threads(0)
        .resolver_threads(0)
        .spawner_threads(0)
        .build()
        .expect("valid config")
}

/// Open `open` connections, half-close the one at `which`, and return how
/// long the server took to close it, or `None` if it stayed open for
/// `limit`.
fn time_to_close<H: AsyncEventHandler>(
    open: usize,
    which: usize,
    limit: Duration,
) -> Option<Duration> {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ACCEPTED.store(0, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<H>()
        .expect("launch");
    let addr = runtime.bound_addr().unwrap();
    let mut conns: Vec<TcpStream> = (0..open)
        .map(|_| TcpStream::connect(addr).expect("connect"))
        .collect();
    wait_accepted(open);

    let mut conn = conns.remove(which);
    // Set before the write shutdown: macOS refuses `setsockopt` once both
    // directions are shut, and the server's FIN can arrive before this
    // call (#778).
    conn.set_read_timeout(Some(limit)).unwrap();
    conn.shutdown(Shutdown::Write).expect("shutdown");
    let start = Instant::now();
    let closed = matches!(conn.read(&mut [0u8; 16]), Ok(0));
    let elapsed = start.elapsed();

    drop(conns);
    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    closed.then_some(elapsed)
}

const CLOSE_LIMIT: Duration = Duration::from_secs(3);

#[test]
fn a_task_that_reads_the_fin_and_returns_closes_the_only_connection() {
    assert!(
        time_to_close::<ReadsToEof>(1, 0, CLOSE_LIMIT).is_some(),
        "the connection stayed open"
    );
}

#[test]
fn a_task_that_reads_the_fin_and_returns_closes_the_first_of_two_connections() {
    assert!(
        time_to_close::<ReadsToEof>(2, 0, CLOSE_LIMIT).is_some(),
        "the connection stayed open"
    );
}

#[test]
fn a_task_that_reads_the_fin_and_returns_closes_the_second_of_two_connections() {
    assert!(
        time_to_close::<ReadsToEof>(2, 1, CLOSE_LIMIT).is_some(),
        "the connection stayed open"
    );
}

#[test]
fn a_task_that_reads_the_fin_and_returns_closes_one_of_four_connections() {
    assert!(
        time_to_close::<ReadsToEof>(4, 2, CLOSE_LIMIT).is_some(),
        "the connection stayed open"
    );
}

/// The peer's FIN finishes the read half and nothing else: a task that does
/// not read keeps the connection open.
#[test]
fn a_fin_does_not_close_a_connection_whose_task_does_not_read() {
    assert!(
        time_to_close::<Sleeps>(1, 0, Duration::from_secs(1)).is_none(),
        "the FIN closed the connection"
    );
}

/// Each connection's task reads until it has seen `bye`, then returns, which
/// closes the connection.
struct EndsOnBye;

impl AsyncEventHandler for EndsOnBye {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        ACCEPTED.fetch_add(1, Ordering::SeqCst);
        async move {
            let mut seen = Vec::new();
            while !seen.ends_with(b"bye") {
                let n = conn
                    .with_data(|d| {
                        seen.extend_from_slice(d);
                        ParseResult::Consumed(d.len())
                    })
                    .await;
                if n == 0 {
                    return;
                }
            }
        }
    }
    fn create_for_worker(_id: usize) -> Self {
        EndsOnBye
    }
}

/// A connection closed because its task ended sends its FIN while another
/// connection is open.
#[test]
fn a_connection_whose_task_ends_is_closed_while_another_is_open() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ACCEPTED.store(0, Ordering::SeqCst);
    let (runtime, handles) = RinglineBuilder::new(config())
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<EndsOnBye>()
        .expect("launch");
    let addr = runtime.bound_addr().unwrap();
    let _other = TcpStream::connect(addr).expect("connect");
    let mut conn = TcpStream::connect(addr).expect("connect");
    wait_accepted(2);

    std::io::Write::write_all(&mut conn, b"bye").unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let closed = matches!(conn.read(&mut [0u8; 16]), Ok(0));

    runtime.shutdown();
    for h in handles {
        h.join().expect("worker panicked").expect("worker failed");
    }
    assert!(closed, "the connection stayed open after its task ended");
}
