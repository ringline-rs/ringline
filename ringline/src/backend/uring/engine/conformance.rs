//! Conformance tests for the kernel behaviour the receive design relies on
//! (`docs/recv-incremental-ring-design.md`, "Kernel behaviour relied on").
//!
//! They drive the engine through [`Engine`] with plain sockets; the CQ
//! overflow test also reads `UringEngine::cq_overflowed`. Tests of
//! incremental rings return early on a kernel without them
//! (`incremental_buffers` is `false`, which is a failure from 6.12), where
//! `incremental_buffers_matches_registration` in `ring.rs` checks the
//! refusal instead.
//!
//! Each test creates its provided ring before the engine, so the engine's
//! ring fd is closed before the provided ring's memory is freed, including
//! when an assertion fails.

use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use super::{ActiveEngine, Engine, RingKind};
use crate::backend::ProvidedBufRing;
use crate::backend::uring::abi::{RecvMsgOut, cqueue};
use crate::backend::uring::ring::is_memlock_enomem;
use crate::backend::uring::sqe::{Fd, Op, Sqe};
use crate::config::ConfigBuilder;
use crate::memlock::KernelVersion;

type Cqe = (u64, i32, u32);

fn engine_with(sq_entries: u32, sqpoll: bool) -> ActiveEngine {
    let config = ConfigBuilder::new()
        .workers(1)
        .sq_entries(sq_entries)
        .sqpoll(sqpoll)
        .build()
        .expect("valid config");
    // Up to 5 s for earlier rings' memlock charge to be released (#589).
    for _ in 0..50 {
        match ActiveEngine::setup(&config) {
            Err(e) if is_memlock_enomem(&e) => std::thread::sleep(Duration::from_millis(100)),
            result => return result.expect("engine"),
        }
    }
    ActiveEngine::setup(&config).expect("engine")
}

fn engine() -> ActiveEngine {
    engine_with(256, false)
}

/// A connected loopback pair: the client writes, the engine receives on
/// the server end.
fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let (server, _) = listener.accept().expect("accept");
    client.set_nodelay(true).expect("nodelay");
    (client, server)
}

fn arm(engine: &mut ActiveEngine, server: &TcpStream, group: u16, user_data: u64) {
    let sqe = Sqe::new(
        Op::RecvMulti {
            fd: Fd::Raw(server.as_raw_fd()),
            buf_group: group,
            limit: 0,
        },
        user_data,
    );
    // Safety: a multishot recv references no caller memory.
    unsafe { engine.push(&sqe) }.expect("push");
}

/// Reap until `n` completions have arrived, or 2 s pass.
fn reap(engine: &mut ActiveEngine, n: usize) -> Vec<Cqe> {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut out = Vec::new();
    while out.len() < n && Instant::now() < deadline {
        engine.submit_and_get_events().expect("enter");
        engine.reap(&mut out);
        if out.len() < n {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    out
}

/// Reap whatever arrives within `window`.
fn reap_for(engine: &mut ActiveEngine, window: Duration) -> Vec<Cqe> {
    let deadline = Instant::now() + window;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        engine.submit_and_get_events().expect("enter");
        engine.reap(&mut out);
        std::thread::sleep(Duration::from_millis(1));
    }
    out
}

fn bytes(ring: &ProvidedBufRing, bid: u16, off: usize, len: usize) -> Vec<u8> {
    let (ptr, size) = ring.get_buffer(bid);
    assert!(off + len <= size as usize);
    // Safety: the range is inside buffer `bid`, which no recv is writing
    // while the test reads it.
    unsafe { std::slice::from_raw_parts(ptr.add(off), len).to_vec() }
}

/// Whether the kernel has incremental rings. A test that returns early on
/// `false` prints so, since the harness reports it as passed. From 6.12 the
/// kernel has them, so `false` there fails the test.
fn incremental(engine: &ActiveEngine) -> bool {
    let inc = engine.incremental_buffers().expect("probe");
    if !inc {
        let kernel = KernelVersion::current();
        assert!(
            kernel
                < Some(KernelVersion {
                    major: 6,
                    minor: 12
                }),
            "incremental rings refused on {kernel:?}"
        );
        eprintln!("skipped: the kernel has no incremental buffer rings");
    }
    inc
}

/// A completion that delivered data, as the receive design reads it.
fn data(cqe: Cqe) -> (i32, Option<u16>, bool, bool, bool) {
    let (_, res, flags) = cqe;
    (
        res,
        cqueue::buffer_select(flags),
        cqueue::buf_more(flags),
        cqueue::more(flags),
        cqueue::sock_nonempty(flags),
    )
}

/// Rows "Multishot RECV on an INC ring" and "The ring entry": successive
/// completions append into one buffer at increasing offsets, each with
/// `F_BUFFER`, the bid and `F_BUF_MORE`; the kernel advances the entry in
/// place.
#[test]
fn inc_completions_append_into_one_buffer() {
    let ring = ProvidedBufRing::new(1, 1, 4096).expect("ring");
    let mut e = engine();
    if !incremental(&e) {
        return;
    }
    e.register_buf_ring(&ring, RingKind::Incremental)
        .expect("register");
    let (mut client, server) = pair();
    arm(&mut e, &server, 1, 1);
    let mut cqes = Vec::new();
    for m in [&b"hello"[..], b"world!"] {
        client.write_all(m).expect("write");
        cqes.extend(reap(&mut e, 1));
    }
    assert_eq!(cqes.len(), 2, "{cqes:?}");
    assert_eq!(data(cqes[0]), (5, Some(0), true, true, false));
    assert_eq!(data(cqes[1]), (6, Some(0), true, true, false));
    assert_eq!(bytes(&ring, 0, 0, 11), b"helloworld!");
    let base = ring.get_buffer(0).0 as u64;
    let (addr, len, bid) = ring.entry(0);
    assert_eq!((addr - base, len, bid), (11, 4096 - 11, 0));
    e.unregister_buf_ring(1).expect("unregister");
}

/// Rows "The completion that uses up a buffer" and "No buffer left": it
/// clears `F_BUF_MORE`, the kernel writes nothing more into the buffer,
/// and the next data ends the arm with `-ENOBUFS` without `F_MORE`. A
/// re-posted buffer is filled from its start.
#[test]
fn inc_buffer_used_up_is_not_written_again_until_posted() {
    let mut ring = ProvidedBufRing::new(2, 1, 16).expect("ring");
    let mut e = engine();
    if !incremental(&e) {
        return;
    }
    e.register_buf_ring(&ring, RingKind::Incremental)
        .expect("register");
    let (mut client, server) = pair();
    arm(&mut e, &server, 2, 2);
    client.write_all(&[b'a'; 16]).expect("write");
    let first = reap(&mut e, 1);
    assert_eq!(first.len(), 1, "{first:?}");
    assert_eq!(data(first[0]), (16, Some(0), false, true, false));
    ring.on_handout();

    client.write_all(b"late").expect("write");
    let second = reap(&mut e, 1);
    assert_eq!(second.len(), 1, "{second:?}");
    assert_eq!(second[0].1, -libc::ENOBUFS);
    assert!(!cqueue::more(second[0].2));
    assert_eq!(bytes(&ring, 0, 0, 16), [b'a'; 16]);

    ring.replenish_batch(&[0]);
    arm(&mut e, &server, 2, 3);
    let third = reap(&mut e, 1);
    assert_eq!(third.len(), 1, "{third:?}");
    assert_eq!(data(third[0]).0, 4);
    assert_eq!(bytes(&ring, 0, 0, 4), b"late");
    e.unregister_buf_ring(2).expect("unregister");
}

/// Row "No buffer left" on a plain ring: one buffer, more data than it
/// holds.
#[test]
fn plain_ring_without_buffers_ends_the_arm_with_enobufs() {
    let ring = ProvidedBufRing::new(3, 1, 16).expect("ring");
    let mut e = engine();
    e.register_buf_ring(&ring, RingKind::Plain)
        .expect("register");
    let (mut client, server) = pair();
    client.write_all(&[b'b'; 32]).expect("write");
    arm(&mut e, &server, 3, 4);
    let cqes = reap(&mut e, 2);
    assert_eq!(cqes.len(), 2, "{cqes:?}");
    assert_eq!(data(cqes[0]).0, 16);
    assert!(cqueue::more(cqes[0].2));
    assert_eq!(cqes[1].1, -libc::ENOBUFS);
    assert!(!cqueue::more(cqes[1].2));
    e.unregister_buf_ring(3).expect("unregister");
}

/// Row "More data queued": a completion carries `SOCK_NONEMPTY` when the
/// socket still has data after it, on both ring kinds.
#[test]
fn sock_nonempty_marks_completions_with_data_left() {
    for kind in [RingKind::Plain, RingKind::Incremental] {
        let ring = ProvidedBufRing::new(4, 4, 16).expect("ring");
        let mut e = engine();
        if kind == RingKind::Incremental && !incremental(&e) {
            continue;
        }
        e.register_buf_ring(&ring, kind).expect("register");
        let (mut client, server) = pair();
        client.write_all(&[b'c'; 40]).expect("write");
        // Let all 40 bytes reach the receive queue before the arm.
        std::thread::sleep(Duration::from_millis(20));
        arm(&mut e, &server, 4, 5);
        let cqes = reap(&mut e, 3);
        let seen: Vec<(i32, bool)> = cqes
            .iter()
            .map(|&(_, res, flags)| (res, cqueue::sock_nonempty(flags)))
            .collect();
        assert_eq!(seen, [(16, true), (16, true), (8, false)], "{kind:?}");
        e.unregister_buf_ring(4).expect("unregister");
    }
}

/// How `check_offset_order` drives the connections.
struct OrderRun {
    sq_entries: u32,
    sqpoll: bool,
    conns: usize,
    /// Write once per connection before reaping anything, instead of 24
    /// rounds reaped as they go.
    burst: bool,
    bufs: u16,
    buf_size: u32,
}

/// Byte-verified order across connections sharing incremental buffers:
/// the data offset is not in the CQE, so the reader derives it from the
/// order completions are reaped in. Connections write stamped chunks; each
/// completion's bytes must be the next bytes its connection sent.
fn check_offset_order(run: OrderRun) {
    const GROUP: u16 = 6;
    let mut ring = ProvidedBufRing::new(GROUP, run.bufs, run.buf_size).expect("ring");
    let mut e = engine_with(run.sq_entries, run.sqpoll);
    if !incremental(&e) {
        return;
    }
    e.register_buf_ring(&ring, RingKind::Incremental)
        .expect("register");
    let conns = run.conns;
    let pairs: Vec<(TcpStream, TcpStream)> = (0..conns).map(|_| pair()).collect();
    let arm_conn = |e: &mut ActiveEngine, conn: usize| {
        arm(e, &pairs[conn].1, GROUP, conn as u64);
    };
    for conn in 0..conns {
        arm_conn(&mut e, conn);
    }
    let mut order = OrderCheck {
        received: vec![0; conns],
        offset: vec![0; run.bufs as usize],
        verified: 0,
        completions: 0,
        arms_ended: 0,
    };
    let mut sent = vec![0usize; conns];
    // A burst writes 1000–1199 bytes per connection, less in all than the
    // ring holds. With 256-byte buffers each receive posts several
    // completions in one task_work run, so the 64-entry CQ overflows even
    // where the kernel runs at most 20 deferred task_work items per pass,
    // and at most two passes per enter (6.13 and later).
    let (rounds, base, span) = if run.burst {
        (1, 1000, 200)
    } else {
        (24, 100, 3000)
    };
    let mut overflowed = false;
    for round in 0..rounds {
        for (conn, (client, _)) in pairs.iter().enumerate() {
            let len = base + (conn * 977 + round * 313) % span;
            let chunk: Vec<u8> = (0..len).map(|k| stamp(conn, sent[conn] + k)).collect();
            (&*client).write_all(&chunk).expect("write");
            sent[conn] += len;
        }
        if run.burst {
            // Let every connection's data reach its socket, then run the
            // queued task_work once without reaping.
            std::thread::sleep(Duration::from_millis(50));
            e.submit_and_get_events().expect("enter");
            overflowed = e.cq_overflowed();
        } else {
            let cqes = reap_for(&mut e, Duration::from_millis(5));
            for conn in order.check(&mut ring, cqes) {
                arm_conn(&mut e, conn);
            }
        }
    }
    let total: usize = sent.iter().sum();
    let deadline = Instant::now() + Duration::from_secs(5);
    while order.verified < total && Instant::now() < deadline {
        let cqes = reap_for(&mut e, Duration::from_millis(10));
        for conn in order.check(&mut ring, cqes) {
            arm_conn(&mut e, conn);
        }
    }
    assert_eq!(order.received, sent);
    if run.burst {
        // A completion that finds the CQ full ends its arm (no `F_MORE`)
        // with data still queued, so the bytes after it arrive only through
        // the re-arm above.
        assert!(overflowed, "the CQ did not overflow");
        assert!(order.arms_ended > 0, "no arm ended on overflow");
        eprintln!(
            "{} completions, {} arms ended",
            order.completions, order.arms_ended
        );
    } else {
        assert_eq!(order.arms_ended, 0, "an arm ended without overflow");
    }
    e.unregister_buf_ring(GROUP).expect("unregister");
}

/// The byte a connection sends at stream position `pos`.
fn stamp(conn: usize, pos: usize) -> u8 {
    (conn * 31 + pos * 7 + pos / 251) as u8
}

/// What `check_offset_order` has verified so far: bytes per connection,
/// and the next write offset in each buffer, derived from reap order.
struct OrderCheck {
    received: Vec<usize>,
    offset: Vec<usize>,
    verified: usize,
    completions: usize,
    arms_ended: usize,
}

impl OrderCheck {
    /// Verify `cqes` and return the connections whose arm ended (no
    /// `F_MORE`), which the caller re-arms.
    fn check(&mut self, ring: &mut ProvidedBufRing, cqes: Vec<Cqe>) -> Vec<usize> {
        let mut ended = Vec::new();
        for (ud, res, flags) in cqes {
            assert!(res > 0, "conn {ud}: res {res}");
            let conn = ud as usize;
            let bid = cqueue::buffer_select(flags).expect("F_BUFFER");
            let off = self.offset[bid as usize];
            let got = bytes(ring, bid, off, res as usize);
            for (k, b) in got.iter().enumerate() {
                let pos = self.received[conn] + k;
                assert_eq!(
                    *b,
                    stamp(conn, pos),
                    "conn {conn} byte {pos} (bid {bid} off {off})"
                );
            }
            self.received[conn] += res as usize;
            self.verified += res as usize;
            self.completions += 1;
            self.offset[bid as usize] += res as usize;
            if !cqueue::buf_more(flags) {
                self.offset[bid as usize] = 0;
                ring.on_handout();
                ring.replenish_batch(&[bid]);
            }
            if !cqueue::more(flags) {
                self.arms_ended += 1;
                ended.push(conn);
            }
        }
        ended
    }
}

/// Row "Data offset": byte-verified order, completions reaped as they
/// arrive.
#[test]
fn inc_offset_order_holds_across_connections() {
    check_offset_order(OrderRun {
        sq_entries: 256,
        sqpoll: false,
        conns: 8,
        burst: false,
        bufs: 4,
        buf_size: 16 * 1024,
    });
}

/// Row "CQ overflow": a 16-entry SQ and 64-entry CQ, 96 connections each
/// writing once into 256-byte buffers before any completion is reaped. The
/// CQ overflows, arms end, and the order holds across the re-arms.
#[test]
fn inc_offset_order_holds_across_a_cq_overflow() {
    check_offset_order(OrderRun {
        sq_entries: 16,
        sqpoll: false,
        conns: 96,
        burst: true,
        bufs: 512,
        buf_size: 256,
    });
}

/// The same as `inc_offset_order_holds_across_connections`, under SQPOLL.
#[test]
fn inc_offset_order_holds_under_sqpoll() {
    check_offset_order(OrderRun {
        sq_entries: 256,
        sqpoll: true,
        conns: 8,
        burst: false,
        bufs: 4,
        buf_size: 16 * 1024,
    });
}

/// EOF on a partly used incremental buffer: the FIN ends the arm with 0
/// and no `F_MORE`, the buffer stays posted with its used bytes, and the
/// next connection's data lands after them.
#[test]
fn inc_eof_leaves_a_partly_used_buffer_posted() {
    let ring = ProvidedBufRing::new(7, 1, 4096).expect("ring");
    let mut e = engine();
    if !incremental(&e) {
        return;
    }
    e.register_buf_ring(&ring, RingKind::Incremental)
        .expect("register");
    let (mut client, server) = pair();
    arm(&mut e, &server, 7, 7);
    client.write_all(b"abc").expect("write");
    let first = reap(&mut e, 1);
    assert_eq!(data(first[0]), (3, Some(0), true, true, false));
    client.shutdown(Shutdown::Write).expect("shutdown");
    let eof = reap(&mut e, 1);
    assert_eq!(eof.len(), 1, "{eof:?}");
    assert_eq!(eof[0].1, 0);
    assert!(!cqueue::more(eof[0].2));
    assert_eq!(cqueue::buffer_select(eof[0].2), None);
    let base = ring.get_buffer(0).0 as u64;
    assert_eq!(ring.entry(0).0 - base, 3);

    let (mut other, other_server) = pair();
    arm(&mut e, &other_server, 7, 8);
    other.write_all(b"xyz").expect("write");
    let next = reap(&mut e, 1);
    assert_eq!(data(next[0]), (3, Some(0), true, true, false));
    assert_eq!(bytes(&ring, 0, 0, 6), b"abcxyz");
    e.unregister_buf_ring(7).expect("unregister");
}

/// Multishot `RECVMSG` (the `timestamps` feature) on an incremental ring:
/// each completion's `io_uring_recvmsg_out` header and payload are written
/// at the completion's offset in the buffer.
#[test]
fn inc_recvmsg_multishot_writes_each_message_at_its_offset() {
    let ring = ProvidedBufRing::new(8, 1, 4096).expect("ring");
    let mut e = engine();
    if !incremental(&e) {
        return;
    }
    e.register_buf_ring(&ring, RingKind::Incremental)
        .expect("register");
    let (mut client, server) = pair();
    // Safety: a zeroed msghdr is valid; no name or control space.
    let msghdr: libc::msghdr = unsafe { std::mem::zeroed() };
    let sqe = Sqe::new(
        Op::RecvMsgMulti {
            fd: Fd::Raw(server.as_raw_fd()),
            msg: &msghdr,
            buf_group: 8,
        },
        9,
    );
    // Safety: the kernel copies `msghdr` when it prepares the request; a
    // multishot RECVMSG does not read it again.
    unsafe { e.push(&sqe) }.expect("push");
    let mut offset = 0usize;
    for m in [&b"hello"[..], b"world!"] {
        client.write_all(m).expect("write");
        let cqes = reap(&mut e, 1);
        assert_eq!(cqes.len(), 1, "{cqes:?}");
        let (_, res, flags) = cqes[0];
        assert!(res > 0, "res {res}");
        assert_eq!(cqueue::buffer_select(flags), Some(0));
        assert!(cqueue::buf_more(flags));
        let buf = bytes(&ring, 0, offset, res as usize);
        let out = RecvMsgOut::parse(&buf, &msghdr).expect("recvmsg header");
        assert_eq!(out.payload_data(), m);
        offset += res as usize;
    }
    e.unregister_buf_ring(8).expect("unregister");
}
