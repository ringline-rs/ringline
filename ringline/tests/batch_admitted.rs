#![allow(clippy::manual_async_fn)]
//! `AsyncSendBuilder::submit_batch_admitted`: a refusal returns every part,
//! guards included, and a batch that waits for pool slots is admitted when
//! they return.

mod common;

use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use ringline::{
    AsyncEventHandler, ConfigBuilder, Connection, GuardBox, ParseResult, RegionId, RinglineBuilder,
    SendGuard, SendPart,
};

/// The guard's length where a scenario needs a zero-copy-sized one.
const GUARD_LEN: usize = 16384;
/// Large enough for one whole TLS record on the unbuffered record layer.
const SLOT: u32 = 16448;
const SLOTS: u16 = 8;

/// A guard over heap memory, reporting `region`.
struct VecGuard {
    data: Vec<u8>,
    region: RegionId,
}

impl SendGuard for VecGuard {
    fn as_ptr_len(&self) -> (*const u8, u32) {
        (self.data.as_ptr(), self.data.len() as u32)
    }
    fn region(&self) -> RegionId {
        self.region
    }
}

fn guard(len: usize) -> GuardBox {
    GuardBox::new(VecGuard {
        data: (0..len).map(|i| (i % 251) as u8).collect(),
        region: RegionId::UNREGISTERED,
    })
}

/// What a scenario's batch resolved to.
#[derive(Debug, Clone, PartialEq)]
struct Outcome {
    /// `None` when the batch was admitted.
    refused: Option<io::ErrorKind>,
    /// Parts in the refusal.
    parts_back: usize,
    /// Byte lengths of the guards in the refusal, in order.
    guard_lens: Vec<u32>,
    /// Whether the batch's first poll was pending.
    waited: bool,
}

static OUTCOMES: Mutex<Vec<(u8, Outcome)>> = Mutex::new(Vec::new());
/// Bytes the waiting scenario queued before its batch.
static FILLED: AtomicUsize = AtomicUsize::new(0);
/// Set by the waiting scenario once its batch is pending.
static WAITING: AtomicBool = AtomicBool::new(false);
/// The registered region (base address, id) for the region scenario.
#[cfg(has_io_uring)]
static REGION: OnceLock<(usize, RegionId)> = OnceLock::new();
#[cfg(not(has_io_uring))]
#[allow(dead_code)]
static REGION: OnceLock<(usize, RegionId)> = OnceLock::new();

/// The tests share statics and run one runtime each; one at a time.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

const EMPTY: u8 = b'e';
const ABORTED: u8 = b'a';
const SHUT: u8 = b's';
const TOO_LARGE: u8 = b'l';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const COPY_OVER_SLOT: u8 = b'c';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const TOO_MANY_PARTS: u8 = b'p';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const TOO_MANY_GUARDS: u8 = b'g';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const OUT_OF_REGION: u8 = b'r';
#[cfg_attr(not(has_io_uring), allow(dead_code))]
const SLAB_FULL: u8 = b'f';
const WAITS: u8 = b'w';

/// The batch the waiting scenario sends once admitted.
const HEADER: &[u8] = b"HDR:";

fn parts_for(scenario: u8) -> Vec<SendPart<'static>> {
    match scenario {
        EMPTY => vec![SendPart::Copy(b""), SendPart::Guard(guard(0))],
        ABORTED | SHUT => vec![SendPart::Copy(b"h"), SendPart::Guard(guard(GUARD_LEN))],
        // More than the whole pool, so it can never be admitted.
        TOO_LARGE => vec![
            SendPart::Copy(b"h"),
            SendPart::Guard(guard(SLOT as usize * SLOTS as usize + 1)),
        ],
        COPY_OVER_SLOT => vec![
            SendPart::Copy(&[b'c'; SLOT as usize + 1]),
            SendPart::Guard(guard(GUARD_LEN)),
        ],
        TOO_MANY_PARTS => {
            let mut parts: Vec<SendPart<'static>> = (0..32).map(|_| SendPart::Copy(b"x")).collect();
            parts.push(SendPart::Guard(guard(GUARD_LEN)));
            parts
        }
        TOO_MANY_GUARDS => (0..9).map(|_| SendPart::Guard(guard(GUARD_LEN))).collect(),
        OUT_OF_REGION => {
            let (_, id) = *REGION.get().expect("region registered");
            // Heap memory claiming the registered region.
            vec![SendPart::Guard(GuardBox::new(VecGuard {
                data: vec![b'r'; GUARD_LEN],
                region: id,
            }))]
        }
        SLAB_FULL => vec![SendPart::Copy(b"h"), SendPart::Guard(guard(GUARD_LEN))],
        WAITS => vec![SendPart::Copy(HEADER), SendPart::Guard(guard(GUARD_LEN))],
        other => panic!("unknown scenario {other}"),
    }
}

fn record(scenario: u8, outcome: Outcome) {
    OUTCOMES.lock().unwrap().push((scenario, outcome));
}

fn refused_outcome(refused: ringline::BatchRefused<'_>, waited: bool) -> Outcome {
    let guard_lens = refused
        .parts
        .iter()
        .filter_map(|p| match p {
            SendPart::Guard(g) => Some(g.as_ptr_len().1),
            SendPart::Copy(_) => None,
        })
        .collect();
    Outcome {
        refused: Some(refused.error.kind()),
        parts_back: refused.parts.len(),
        guard_lens,
        waited,
    }
}

/// Fill the send pool with bounded sends until one has to wait. The client
/// does not read until `WAITING` is set, so the socket fills and the sends
/// queued hold their slots. Returns the bytes queued.
async fn fill_pool(conn: &mut Connection) -> usize {
    let chunk = vec![b'f'; SLOT as usize];
    let mut queued = 0usize;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let admitted = {
            let mut send = pin!(conn.send_admitted(&chunk));
            std::future::poll_fn(|cx| Poll::Ready(send.as_mut().poll(cx))).await
        };
        match admitted {
            Poll::Ready(Ok(_)) => queued += chunk.len(),
            Poll::Ready(Err(e)) => panic!("filling the pool: {e}"),
            Poll::Pending => return queued,
        }
        assert!(Instant::now() < deadline, "the pool never filled");
        ringline::sleep(Duration::from_millis(1)).await;
    }
}

struct Scenarios;

impl AsyncEventHandler for Scenarios {
    fn on_accept(&self, mut conn: Connection) -> impl Future<Output = ()> + 'static {
        async move {
            let mut trigger = 0u8;
            let n = conn
                .with_data(|data| {
                    trigger = data[0];
                    ParseResult::Consumed(data.len())
                })
                .await;
            if n == 0 {
                return;
            }
            match trigger {
                ABORTED => conn.abort(),
                SHUT => conn.shutdown_write(),
                SLAB_FULL => {
                    // Holds the only slab entry: a zero-copy batch larger than
                    // the socket takes while the client does not read.
                    let big = vec![SendPart::Guard(guard(8 << 20))];
                    let _held = conn.send_parts().submit_batch(big).expect("first batch");
                    let outcome = match conn
                        .send_parts()
                        .submit_batch_admitted(parts_for(SLAB_FULL))
                        .await
                    {
                        Ok(_) => Outcome {
                            refused: None,
                            parts_back: 0,
                            guard_lens: Vec::new(),
                            waited: false,
                        },
                        Err(r) => refused_outcome(r, false),
                    };
                    record(SLAB_FULL, outcome);
                    return;
                }
                WAITS => {
                    FILLED.store(fill_pool(&mut conn).await, Ordering::SeqCst);
                    let mut batch = pin!(conn.send_parts().submit_batch_admitted(parts_for(WAITS)));
                    let first =
                        std::future::poll_fn(|cx| Poll::Ready(batch.as_mut().poll(cx))).await;
                    let (waited, result) = match first {
                        Poll::Ready(r) => (false, r),
                        Poll::Pending => {
                            WAITING.store(true, Ordering::SeqCst);
                            (true, batch.await)
                        }
                    };
                    let outcome = match result {
                        Ok((n, sent)) => {
                            sent.await.expect("the admitted batch settles");
                            Outcome {
                                refused: None,
                                parts_back: n,
                                guard_lens: Vec::new(),
                                waited,
                            }
                        }
                        Err(r) => refused_outcome(r, waited),
                    };
                    record(WAITS, outcome);
                    while conn
                        .with_data(|data| ParseResult::Consumed(data.len()))
                        .await
                        > 0
                    {}
                    return;
                }
                _ => {}
            }
            let outcome = match conn
                .send_parts()
                .submit_batch_admitted(parts_for(trigger))
                .await
            {
                Ok((n, _sent)) => Outcome {
                    refused: None,
                    parts_back: n,
                    guard_lens: Vec::new(),
                    waited: false,
                },
                Err(r) => refused_outcome(r, false),
            };
            record(trigger, outcome);
        }
    }

    fn create_for_worker(_id: usize) -> Self {
        Scenarios
    }
}

fn launch(
    slab_slots: u16,
    tls: Option<ringline::TlsConfig>,
) -> (
    ringline::Runtime,
    Vec<std::thread::JoinHandle<Result<(), ringline::Error>>>,
) {
    let mut builder = ConfigBuilder::new()
        .workers(1)
        .pin_to_core(false)
        .sq_entries(64)
        .max_connections(16)
        .send_pool(SLOTS, SLOT)
        .send_slab_slots(slab_slots)
        .max_registered_regions(4);
    if let Some(tls) = tls {
        builder = builder.tls(tls);
    }
    let config = builder.build().expect("valid config");
    RinglineBuilder::new(config)
        .bind("127.0.0.1:0".parse().unwrap())
        .launch::<Scenarios>()
        .expect("launch")
}

fn wait_outcome(scenario: u8) -> Outcome {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        {
            let mut outcomes = OUTCOMES.lock().unwrap();
            if let Some(pos) = outcomes.iter().position(|(s, _)| *s == scenario) {
                return outcomes.remove(pos).1;
            }
        }
        assert!(
            Instant::now() < deadline,
            "scenario {scenario} never resolved"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// Runs a refusal scenario over plaintext and returns its outcome.
fn run(scenario: u8, slab_slots: u16) -> Outcome {
    let (runtime, handles) = launch(slab_slots, None);
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream.write_all(&[scenario]).unwrap();
    let outcome = wait_outcome(scenario);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    outcome
}

fn assert_refused(outcome: &Outcome, kind: io::ErrorKind, parts: usize, guard_lens: &[u32]) {
    assert_eq!(outcome.refused, Some(kind), "{outcome:?}");
    assert_eq!(
        outcome.parts_back, parts,
        "every part comes back: {outcome:?}"
    );
    assert_eq!(
        outcome.guard_lens, guard_lens,
        "every guard comes back: {outcome:?}"
    );
}

#[test]
fn an_empty_batch_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(EMPTY, 64);
    assert_refused(&outcome, io::ErrorKind::InvalidInput, 2, &[0]);
}

#[test]
fn a_batch_after_abort_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(ABORTED, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::ConnectionAborted,
        2,
        &[GUARD_LEN as u32],
    );
}

#[test]
fn a_batch_after_shutdown_write_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(SHUT, 64);
    assert_refused(&outcome, io::ErrorKind::BrokenPipe, 2, &[GUARD_LEN as u32]);
}

/// On mio the whole batch is copied, so a batch longer than the pool can
/// never be admitted. On io_uring a plaintext batch's guards take no pool
/// slot, so the same batch is sent.
#[cfg(not(has_io_uring))]
#[test]
fn a_batch_longer_than_the_pool_is_refused_with_its_parts() {
    let _serial = serial();
    let outcome = run(TOO_LARGE, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        2,
        &[SLOT * SLOTS as u32 + 1],
    );
}

#[cfg(has_io_uring)]
#[test]
fn copy_parts_over_one_slot_are_refused_with_their_parts() {
    let _serial = serial();
    let outcome = run(COPY_OVER_SLOT, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        2,
        &[GUARD_LEN as u32],
    );
}

#[cfg(has_io_uring)]
#[test]
fn more_than_32_parts_are_refused_with_their_parts() {
    let _serial = serial();
    let outcome = run(TOO_MANY_PARTS, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        33,
        &[GUARD_LEN as u32],
    );
}

#[cfg(has_io_uring)]
#[test]
fn more_than_8_guards_are_refused_with_their_parts() {
    let _serial = serial();
    let outcome = run(TOO_MANY_GUARDS, 64);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        9,
        &[GUARD_LEN as u32; 9],
    );
}

#[cfg(has_io_uring)]
#[test]
fn a_guard_outside_its_region_is_refused_with_its_parts() {
    use ringline::MemoryRegion;
    const REGION_LEN: usize = 1 << 16;
    let _serial = serial();
    let (runtime, handles) = launch(64, None);
    if REGION.get().is_none() {
        let backing: &'static mut [u8] = Box::leak(vec![0u8; REGION_LEN].into_boxed_slice());
        // SAFETY: leaked, so valid and unmoved for the life of the process.
        let region = unsafe { MemoryRegion::new(backing.as_mut_ptr(), REGION_LEN) };
        // As `disk_fixed_buffers.rs`: retry a transient ENOMEM or EFAULT.
        let deadline = Instant::now() + Duration::from_secs(5);
        let id = loop {
            match runtime.register_region(region.clone()) {
                Ok(id) => break id,
                Err(e) => {
                    let msg = e.to_string();
                    let transient = msg.contains("(ENOMEM)") || msg.contains("(EFAULT)");
                    assert!(
                        transient && Instant::now() < deadline,
                        "register_region: {e}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        REGION.set((backing.as_mut_ptr() as usize, id)).unwrap();
    }
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream.write_all(&[OUT_OF_REGION]).unwrap();
    let outcome = wait_outcome(OUT_OF_REGION);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        1,
        &[GUARD_LEN as u32],
    );
}

/// With one slab entry, held by a zero-copy send the client does not read, a
/// waiting batch with a guard is admitted for its slot and refused for the
/// slab.
#[cfg(has_io_uring)]
#[test]
fn a_full_slab_refuses_a_batch_with_its_parts() {
    let _serial = serial();
    let outcome = run(SLAB_FULL, 1);
    assert_refused(&outcome, io::ErrorKind::Other, 2, &[GUARD_LEN as u32]);
}

/// The pool is full of sends to a client that does not read. The batch's
/// first poll is pending; once the client reads, the slots return and the
/// batch is admitted and delivered after the queued bytes.
#[test]
fn a_waiting_batch_is_admitted_when_slots_return() {
    let _serial = serial();
    WAITING.store(false, Ordering::SeqCst);
    let (runtime, handles) = launch(64, None);
    let mut stream = TcpStream::connect(runtime.bound_addr().expect("bound address")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    stream.write_all(&[WAITS]).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !WAITING.load(Ordering::SeqCst) {
        if let Some((_, o)) = OUTCOMES.lock().unwrap().iter().find(|(s, _)| *s == WAITS) {
            panic!("the batch resolved without waiting: {o:?}");
        }
        assert!(Instant::now() < deadline, "the batch never waited");
        std::thread::sleep(Duration::from_millis(1));
    }
    let filled = FILLED.load(Ordering::SeqCst);
    let mut got = vec![0u8; filled + HEADER.len() + GUARD_LEN];
    stream.read_exact(&mut got).expect("every byte delivered");
    let outcome = wait_outcome(WAITS);
    assert_eq!(
        outcome,
        Outcome {
            refused: None,
            parts_back: 2,
            guard_lens: Vec::new(),
            waited: true,
        }
    );
    assert!(got[..filled].iter().all(|&b| b == b'f'));
    assert_eq!(&got[filled..filled + HEADER.len()], HEADER);
    let value: Vec<u8> = (0..GUARD_LEN).map(|i| (i % 251) as u8).collect();
    assert_eq!(&got[filled + HEADER.len()..], &value[..]);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
}

/// Over TLS every part is copied and the batch waits for the ciphertext
/// bound of its length, so one longer than the pool is refused, with its
/// parts.
#[test]
fn a_tls_batch_longer_than_the_pool_is_refused_with_its_parts() {
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};
    use std::sync::Arc;

    let _serial = serial();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let tls = ringline::TlsConfig::builder()
        .cert(vec![der.clone()], key.into())
        .build()
        .expect("tls config");
    let (runtime, handles) = launch(64, Some(tls));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(der).unwrap();
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from("localhost").unwrap();
    let client = rustls::ClientConnection::new(Arc::new(client_config), server_name).unwrap();
    let sock = TcpStream::connect(runtime.bound_addr().expect("bound")).expect("connect");
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut stream = rustls::StreamOwned::new(client, sock);
    stream.write_all(&[TOO_LARGE]).expect("handshake and write");
    let outcome = wait_outcome(TOO_LARGE);
    drop(stream);
    runtime.shutdown();
    common::join_workers(&runtime, handles);
    assert_refused(
        &outcome,
        io::ErrorKind::InvalidInput,
        2,
        &[SLOT * SLOTS as u32 + 1],
    );
}
