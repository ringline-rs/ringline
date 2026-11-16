//! A deterministic discrete-event model of one ringline worker's send copy
//! pool, its send-capacity FIFO, and the kernel socket buffers of the
//! connections it sends on: Experiment C's stage C1
//! (`docs/send-admission-design.md`, section 4, "Admission orders" and
//! "Experiment C"), extended for Experiment D. It runs an admission order
//! against the load of Experiment B's contended case, with slow readers,
//! draining peers, sends outside the FIFO and pipelined replies added, and
//! reports how long the large reply at the head of the FIFO waits. For
//! Experiment D it also sends large replies in pieces, optionally gated on
//! room in the socket, and counts the send queue in truesize.
//!
//! The model reimplements the policy and calls nothing in ringline. Each
//! order's admission pass is in [`policy`], apart from the event machinery.
//!
//! Pool. A reply of `len` bytes takes ceil(len / slot size) slots, all at
//! admission, as `bounded_send_slots` reserves the whole message. Under O5
//! there are two pools; every other order has one.
//!
//! Slot return. A connection's admitted slots wait in its send queue and go
//! to the kernel in runs of up to `--run-slots` (default 32, ringline's
//! `MAX_IOVECS`), one run at a time per connection, as `submit_coalesced_run`
//! builds one `sendmsg`. A run can hold slots of several replies on the
//! connection. A run's slots return together once all of its bytes are in the
//! kernel buffer, as `handle_send_msg_coalesced` releases them only on the
//! run's full completion. `--run-slots 1` returns each slot when its own
//! bytes are in.
//!
//! Kernel buffer. Each connection's kernel buffer holds K bytes and drains
//! linearly at its peer's read rate; drain times are computed, not stepped. A
//! send writes while k < K (`wmem_queued < sndbuf`). A send that filled the
//! buffer resumes when k falls to `--writable` x K (`POLLOUT` needs free space
//! of at least `wmem_queued / 2`), or at the next tick of ringline's send
//! backstop (`--backstop-ms`, `SEND_BACKSTOP_INTERVAL`), which resubmits every
//! waiting send, whichever comes first. A reply settles when its last byte is
//! in the buffer, which is when its `SendCompletion` resolves, and is
//! delivered when the peer has read its last byte.
//!
//! Truesize. The paragraph above is the model at its defaults. Given a peer
//! receive window W (`--rwnd` and the per-kind `--*-rwnd`, part of K), a
//! segment size (`--seg` and `--*-seg`) and `--skb-overhead`, K splits into
//! the peer's receive buffer, W bytes of payload, and the send queue,
//! `sk_sndbuf` = K - W bytes of truesize. Bytes leave the send queue once the
//! peer's receive buffer takes them: by time t, the first
//! min(written, read(t) + W) bytes, with no delay, as on loopback. The
//! queue's truesize, q, is its payload plus `--skb-overhead` for each segment
//! not wholly out of the queue, as `tcp_stream_alloc_skb` charges
//! `SKB_TRUESIZE` of the skb head and `skb_copy_to_page_nocache` and
//! `tcp_trim_head` charge and release payload byte for byte. A write first
//! tops up the queue's last segment to the segment size, then starts each new
//! segment only while q < `sk_sndbuf`, as `tcp_sendmsg_locked` checks
//! `sk_stream_memory_free` only at `new_segment`, so the last segment can take
//! q past `sk_sndbuf` by up to one segment. `POLLOUT` holds while
//! q <= `--writable` x `sk_sndbuf`; at the default of 2/3 that is
//! `__sk_stream_is_writeable`'s q + q / 2 <= `sk_sndbuf` to within a byte.
//! With a segment size of 0, a write is cut at the buffer's limit and q is
//! the payload alone, which with W = 0 is the model above.
//!
//! Server. As `admission-server`, one task per connection: it reads a
//! request, builds the reply, waits in the FIFO for admission, and reads the
//! next request once fewer than `--pipeline` of its replies are admitted and
//! unsettled; with the default of 1 that is admission-server's loop. The
//! task waits for one reply's admission before it reads the next request, so
//! a connection has at most one waiter. A waiter not admitted within
//! `--admit-ms` of joining is removed and its connection aborted. A
//! connection's oldest unsettled reply is timed from its admission
//! or, if later, from the settlement of the reply before it on the same
//! connection, and the connection is aborted when that reaches
//! `--settle-ms`. With `--pipeline 1` that is admission-server's settle limit,
//! measured from admission. An abort returns every slot the connection
//! holds, drops its waiters and unread requests, and discards its kernel
//! buffer, so its peer loses what it had not read. Under O1 a small reply
//! takes slots at once or is refused, which aborts its connection
//! (admission-server's `send` arm).
//!
//! Pieces. With `--stream-piece` p above 0, a reply that is not small and has
//! more than p bytes is sent as ceil(n / p) pieces, as admission-server's
//! `--stream-piece` in D's harness does. Each piece is a waiter of its own,
//! with its own slots and its own `--admit-ms` from joining the FIFO, and
//! settles on its own. The next piece starts when the one before it settles,
//! so a reply has at most one piece waiting or unsettled. The connection reads
//! no request from its first piece's start to its last piece's admission; the
//! last piece then counts against `--pipeline` as one reply. Each piece is
//! timed from its admission, as any reply is, and its connection is aborted
//! when that reaches `--settle-ms`. With `--stream-gate`, a piece first waits
//! for `POLLOUT` on its socket, q <= `--writable` x `sk_sndbuf` (see
//! Truesize), and its connection is aborted when that wait reaches
//! `--settle-ms`.
//!
//! Load. As `admission-load`: `--small-conns` connections offer requests at
//! `--small-rate` per second in total, open loop, evenly spaced, and read at
//! `--fast-read-bps`; `--slow-conns` connections do the same at `--slow-rate`
//! each and read at `--slow-read-bps`. A connection the server ends loses its
//! unread replies and reconnects at once, and its schedule continues. Every
//! `--episode-ms` from the start of the window, `--stall-peers` peers that
//! never read and `--drainers` peers that read at `--drain-read-bps` each ask
//! for one reply, and `--large-delay-ms` later one fast-reading connection
//! asks for `--large-size`: the episode's head. The drainers ask at the
//! episode's start. With `--stall-gap-us` above 0, stalled peer i asks
//! i x the gap after the start, as admission-load connects and writes them
//! one after another, and the head asks `--large-delay-ms` plus one gap after
//! the last, as admission-load sleeps after the last write and then connects;
//! at 0 every stalled peer asks at the start and the head `--large-delay-ms`
//! after it. The stalled peers and drainers close 100 ms before the episode
//! ends, as admission-load's stalled peers do; a close that finds the server
//! still sending to the peer is counted as a peer reset.
//! `--outside-conns` fast-reading connections receive sends that
//! take slots without the FIFO, at `--outside-rate` per second in total, each
//! dropped when the free slots do not cover it; they are not timed and never
//! end their connection.
//!
//! Statistics count only requests scheduled inside the window, and the run
//! continues for `--admit-ms` + 2 s after it, admission-load's drain. A
//! reply's admission delay is reported from its scheduled send time, which
//! includes the time a request waits unread while its connection's earlier
//! reply waits, and from joining the FIFO. L is the main-pool slots held by
//! small replies of fast and of slow readers, time-averaged over each head's
//! wait, from its joining the FIFO to its admission or removal. Each episode
//! lists the sends admitted ahead of its head while it waited, and how long
//! each held its slots. With pieces, the head's admission and wait are its
//! first piece's.
//!
//! Experiment D's statistics, under `d` and in each episode: per head, whether
//! the client read all of it, the time from its request to its last byte, and
//! the fewest free main-pool slots from its request to its last byte, both at
//! every change and in samples every `--sample-ms` (0: no samples), as D's
//! admission-server samples `main_free`; whether each drainer's reply was read
//! whole before its connection ended; the sends of large replies (pieces, or
//! whole replies) and those that waited for room in the socket, by the kind of
//! connection; the pieces that waited at the gate; and the connections ended
//! by each cause, by kind.
//!
//! Determinism. Time is integer nanoseconds. One event queue, ordered by time
//! and then by the order the events were scheduled. An event and what it sets
//! off at the same instant (writes, requests read, admission passes) finish
//! before the next event runs. Every collection that affects a result is a
//! vector, deque, or B-tree set or map. `--seed` above 0 adds a
//! uniform phase of up to one interval to each open-loop connection's
//! schedule, drawn from a splitmix64 generator; 0 keeps admission-load's
//! phases.
//!
//! Prints one JSON object: every parameter, and the results.

use std::cmp::Ordering;
use std::collections::{BTreeSet, BinaryHeap, VecDeque};

use clap::Parser;
use serde_json::{Value, json};

use policy::{Grant, MAIN, Order, SMALL_POOL};

const MS: u64 = 1_000_000;
const SEC: u64 = 1_000_000_000;

/// Reply classes, as admission-server's `--small-max` splits them.
const SMALL: usize = 0;
const LARGE: usize = 1;

/// Indices of `Sim::held`: main-pool slots held by small replies of fast and
/// of slow readers and by outside sends (L), then the slots of admitted small
/// replies of fast and of slow readers that have not settled (L unsettled).
const HELD_FAST: usize = 0;
const HELD_SLOW: usize = 1;
const HELD_OUTSIDE: usize = 2;
const UNSETTLED_FAST: usize = 3;
const UNSETTLED_SLOW: usize = 4;
const HELD_COUNTERS: usize = 5;

/// Where a reply came from, for the statistics: the fast and slow small
/// connections, and everything an episode opens.
const FAST: usize = 0;
const SLOW: usize = 1;
const EPISODE: usize = 2;

#[derive(Parser, Clone, Debug)]
#[command(
    name = "admission-model",
    about = "Experiment C's discrete-event model of one worker's send admission"
)]
struct Args {
    #[arg(long, value_enum, default_value_t = Order::O0)]
    order: Order,
    /// 0 keeps admission-load's evenly spaced phases. Above 0, each open-loop
    /// connection's schedule also gets a uniform phase of up to one interval.
    #[arg(long, default_value_t = 0)]
    seed: u64,
    /// Seconds before the window.
    #[arg(long, default_value_t = 4)]
    warmup: u64,
    /// Seconds of window.
    #[arg(long, default_value_t = 40)]
    duration: u64,

    /// A waiter not admitted within this many ms of joining the FIFO is
    /// removed and its connection aborted. Also the small replies' "within"
    /// bound, as Experiment B sets admission-load's `--within-ms`.
    #[arg(long, default_value_t = 1000)]
    admit_ms: u64,
    /// A connection whose oldest unsettled reply has been unsettled this long
    /// is aborted (see the module docs for when the clock starts).
    #[arg(long, default_value_t = 1000)]
    settle_ms: u64,
    /// Replies per connection admitted and not yet settled before the server
    /// stops reading that connection's requests.
    #[arg(long, default_value_t = 1)]
    pipeline: usize,
    /// Replies of at most this many bytes are small.
    #[arg(long, default_value_t = 4096)]
    small_max: u64,

    /// Pool slots (every order but O5).
    #[arg(long, default_value_t = 512)]
    pool_slots: u32,
    /// Pool slot size in bytes (every order but O5).
    #[arg(long, default_value_t = 16384)]
    slot_size: u64,
    /// O5: small-pool slots. Given with `--large-pool-slots`, it replaces the
    /// split by `--small-pool-share`.
    #[arg(long)]
    small_pool_slots: Option<u32>,
    /// O5: large-pool slots, given with `--small-pool-slots`.
    #[arg(long)]
    large_pool_slots: Option<u32>,
    /// O5: the share of `--pool-slots` x `--slot-size` bytes the small pool
    /// takes when the pool sizes are not given; the large pool takes the rest.
    #[arg(long, default_value_t = 0.125)]
    small_pool_share: f64,
    /// O5: small-pool slot size. A reply that fits one takes the small pool.
    #[arg(long, default_value_t = 16384)]
    small_slot_size: u64,
    /// O5: large-pool slot size.
    #[arg(long, default_value_t = 1 << 20)]
    large_slot_size: u64,
    /// Slots per `sendmsg` run; a run's slots return together.
    #[arg(long, default_value_t = 32)]
    run_slots: usize,
    /// O6: how long, from the head joining the FIFO, sends may pass it.
    /// Default: `--admit-ms` / 2.
    #[arg(long)]
    o6_ms: Option<u64>,
    /// O7: R, the most slots sends admitted past heads may hold. Default:
    /// (P - H) / 2 for the H of a `--large-size` reply.
    #[arg(long)]
    budget: Option<u32>,

    /// Kernel send buffer, in bytes, of fast-reading connections.
    #[arg(long, default_value_t = 1 << 20)]
    kbuf: u64,
    /// Kernel buffer of the stalled peers: the send buffer and what the
    /// peer's receive buffer takes before its window closes.
    #[arg(long, default_value_t = (1 << 20) + 4096)]
    stall_kbuf: u64,
    /// A send that filled the buffer resumes when occupancy falls to this
    /// fraction of K.
    #[arg(long, default_value_t = 2.0 / 3.0)]
    writable: f64,
    /// Read rate of fast readers, bytes per second.
    #[arg(long, default_value_t = 1 << 30)]
    fast_read_bps: u64,
    /// Interval of ringline's send backstop, which resubmits every waiting
    /// send; 0 turns it off.
    #[arg(long, default_value_t = 1000)]
    backstop_ms: u64,
    /// Payload bytes of `--kbuf` that the peer's receive buffer of a
    /// fast-reading connection takes (see Truesize in the module docs).
    #[arg(long, default_value_t = 0)]
    rwnd: u64,
    /// Largest segment payload on fast-reading connections; 0: no segments.
    /// Linux sizes a segment to the MSS, at most half the largest window
    /// the peer has advertised (`tcp_bound_to_half_wnd`).
    #[arg(long, default_value_t = 0)]
    seg: u64,
    /// Truesize of a segment beyond its payload, on connections with
    /// segments. On Linux 6.12 with `MAX_TCP_HEADER` of 320 B, the skb head
    /// comes from `skb_small_head_cache` and costs SKB_TRUESIZE(320) = 896 B
    /// (derived from the source, not measured).
    #[arg(long, default_value_t = 0)]
    skb_overhead: u64,
    /// Large replies of more than this many bytes are sent in pieces of
    /// this many; 0 sends every reply whole.
    #[arg(long, default_value_t = 0)]
    stream_piece: u64,
    /// Each piece waits for `POLLOUT` on its socket before it joins the FIFO.
    #[arg(long)]
    stream_gate: bool,
    /// Interval of the free-slot samples; 0 takes none.
    #[arg(long, default_value_t = 0)]
    sample_ms: u64,

    #[arg(long, default_value_t = 16)]
    small_conns: usize,
    /// Small requests per second, over all small connections.
    #[arg(long, default_value_t = 2000)]
    small_rate: u64,
    #[arg(long, default_value_t = 256)]
    small_size: u64,
    #[arg(long, default_value_t = 0)]
    slow_conns: usize,
    /// Requests per second on each slow connection.
    #[arg(long, default_value_t = 100)]
    slow_rate: u64,
    #[arg(long, default_value_t = 4096)]
    slow_size: u64,
    #[arg(long, default_value_t = 1 << 20)]
    slow_read_bps: u64,
    #[arg(long, default_value_t = 1 << 20)]
    slow_kbuf: u64,
    #[arg(long, default_value_t = 0)]
    slow_rwnd: u64,
    #[arg(long, default_value_t = 0)]
    slow_seg: u64,
    /// Connections that receive sends outside the FIFO.
    #[arg(long, default_value_t = 4)]
    outside_conns: usize,
    /// Sends outside the FIFO per second, over all outside connections.
    #[arg(long, default_value_t = 0)]
    outside_rate: u64,
    #[arg(long, default_value_t = 4096)]
    outside_size: u64,

    #[arg(long, default_value_t = 4000)]
    episode_ms: u64,
    #[arg(long, default_value_t = 3)]
    stall_peers: usize,
    #[arg(long, default_value_t = 3 << 20)]
    stall_size: u64,
    /// Microseconds between stalled peers' requests; 0 sends them together.
    #[arg(long, default_value_t = 0)]
    stall_gap_us: u64,
    /// The part of `--stall-kbuf` the peer's receive buffer takes.
    #[arg(long, default_value_t = 0)]
    stall_rwnd: u64,
    #[arg(long, default_value_t = 0)]
    stall_seg: u64,
    #[arg(long, default_value_t = 0)]
    drainers: usize,
    #[arg(long, default_value_t = 3 << 20)]
    drain_size: u64,
    #[arg(long, default_value_t = 8 << 20)]
    drain_read_bps: u64,
    #[arg(long, default_value_t = 1 << 20)]
    drain_kbuf: u64,
    #[arg(long, default_value_t = 0)]
    drain_rwnd: u64,
    #[arg(long, default_value_t = 0)]
    drain_seg: u64,
    #[arg(long, default_value_t = 200)]
    large_delay_ms: u64,
    #[arg(long, default_value_t = 7 << 20)]
    large_size: u64,
}

impl Args {
    /// Every parameter, by its argument id, as the run used it.
    fn params(&self) -> Value {
        let fields: [(&str, Value); 56] = [
            ("order", json!(self.order.name())),
            ("seed", json!(self.seed)),
            ("warmup", json!(self.warmup)),
            ("duration", json!(self.duration)),
            ("admit_ms", json!(self.admit_ms)),
            ("settle_ms", json!(self.settle_ms)),
            ("pipeline", json!(self.pipeline)),
            ("small_max", json!(self.small_max)),
            ("pool_slots", json!(self.pool_slots)),
            ("slot_size", json!(self.slot_size)),
            ("small_pool_slots", json!(self.small_pool_slots)),
            ("large_pool_slots", json!(self.large_pool_slots)),
            ("small_pool_share", json!(self.small_pool_share)),
            ("small_slot_size", json!(self.small_slot_size)),
            ("large_slot_size", json!(self.large_slot_size)),
            ("run_slots", json!(self.run_slots)),
            ("o6_ms", json!(self.o6_ms)),
            ("budget", json!(self.budget)),
            ("kbuf", json!(self.kbuf)),
            ("stall_kbuf", json!(self.stall_kbuf)),
            ("writable", json!(self.writable)),
            ("fast_read_bps", json!(self.fast_read_bps)),
            ("backstop_ms", json!(self.backstop_ms)),
            ("rwnd", json!(self.rwnd)),
            ("seg", json!(self.seg)),
            ("skb_overhead", json!(self.skb_overhead)),
            ("stream_piece", json!(self.stream_piece)),
            ("stream_gate", json!(self.stream_gate)),
            ("sample_ms", json!(self.sample_ms)),
            ("small_conns", json!(self.small_conns)),
            ("small_rate", json!(self.small_rate)),
            ("small_size", json!(self.small_size)),
            ("slow_conns", json!(self.slow_conns)),
            ("slow_rate", json!(self.slow_rate)),
            ("slow_size", json!(self.slow_size)),
            ("slow_read_bps", json!(self.slow_read_bps)),
            ("slow_kbuf", json!(self.slow_kbuf)),
            ("slow_rwnd", json!(self.slow_rwnd)),
            ("slow_seg", json!(self.slow_seg)),
            ("outside_conns", json!(self.outside_conns)),
            ("outside_rate", json!(self.outside_rate)),
            ("outside_size", json!(self.outside_size)),
            ("episode_ms", json!(self.episode_ms)),
            ("stall_peers", json!(self.stall_peers)),
            ("stall_size", json!(self.stall_size)),
            ("stall_gap_us", json!(self.stall_gap_us)),
            ("stall_rwnd", json!(self.stall_rwnd)),
            ("stall_seg", json!(self.stall_seg)),
            ("drainers", json!(self.drainers)),
            ("drain_size", json!(self.drain_size)),
            ("drain_read_bps", json!(self.drain_read_bps)),
            ("drain_kbuf", json!(self.drain_kbuf)),
            ("drain_rwnd", json!(self.drain_rwnd)),
            ("drain_seg", json!(self.drain_seg)),
            ("large_delay_ms", json!(self.large_delay_ms)),
            ("large_size", json!(self.large_size)),
        ];
        Value::Object(
            fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    /// Each pool's slots and slot size, indexed by [`MAIN`] and
    /// [`SMALL_POOL`]. Every order but O5 has one pool, and the small pool
    /// has no slots.
    fn pools(&self) -> Result<([u32; 2], [u64; 2]), String> {
        if self.order != Order::O5 {
            return Ok(([self.pool_slots, 0], [self.slot_size, 1]));
        }
        let (small, large) = match (self.small_pool_slots, self.large_pool_slots) {
            (Some(small), Some(large)) => (small, large),
            (None, None) => {
                let total = u64::from(self.pool_slots) * self.slot_size;
                let small = (total as f64 * self.small_pool_share) as u64 / self.small_slot_size;
                let large = (total - small * self.small_slot_size) / self.large_slot_size;
                (small as u32, large as u32)
            }
            _ => return Err("--small-pool-slots and --large-pool-slots are given together".into()),
        };
        Ok(([large, small], [self.large_slot_size, self.small_slot_size]))
    }

    /// The slots a reply of `len` bytes needs from `pool`.
    fn slots(&self, len: u64, slot_size: [u64; 2]) -> (usize, u32) {
        let pool = self.order.pool(len, slot_size[SMALL_POOL]);
        (pool, len.div_ceil(slot_size[pool]) as u32)
    }

    /// The kernel buffer of a connection of `kind`.
    fn socket(&self, kind: Kind) -> Socket {
        let (kbuf, rwnd, seg, read_bps) = match kind {
            Kind::Fast | Kind::Large | Kind::Outside => {
                (self.kbuf, self.rwnd, self.seg, self.fast_read_bps)
            }
            Kind::Slow => (
                self.slow_kbuf,
                self.slow_rwnd,
                self.slow_seg,
                self.slow_read_bps,
            ),
            Kind::Stall => (self.stall_kbuf, self.stall_rwnd, self.stall_seg, 0),
            Kind::Drain => (
                self.drain_kbuf,
                self.drain_rwnd,
                self.drain_seg,
                self.drain_read_bps,
            ),
        };
        Socket {
            kbuf,
            rwnd,
            seg,
            overhead: if seg > 0 { self.skb_overhead } else { 0 },
            read_bps,
        }
    }

    /// O6's D in nanoseconds.
    fn o6_ns(&self) -> u64 {
        self.o6_ms.unwrap_or(self.admit_ms / 2) * MS
    }

    /// O7's R: `--budget`, or (P - H) / 2 for a `--large-size` head.
    fn budget(&self, capacity: [u32; 2], slot_size: [u64; 2]) -> u32 {
        self.budget.unwrap_or_else(|| {
            let (_, head) = self.slots(self.large_size, slot_size);
            capacity[MAIN].saturating_sub(head) / 2
        })
    }

    /// Rejects parameters the model cannot run.
    fn check(&self) -> Result<(), String> {
        let (capacity, slot_size) = self.pools()?;
        if slot_size.contains(&0) || capacity[MAIN] == 0 {
            return Err("every pool needs slots of at least one byte".into());
        }
        for kind in [Kind::Fast, Kind::Slow, Kind::Stall, Kind::Drain] {
            let s = self.socket(kind);
            if s.rwnd >= s.kbuf {
                return Err("every kernel buffer holds more than its peer's receive window".into());
            }
        }
        if self.stream_gate && self.stream_piece == 0 {
            return Err("--stream-gate needs --stream-piece".into());
        }
        if !(0.0..1.0).contains(&self.writable) {
            return Err("--writable is at least 0 and below 1".into());
        }
        if self.run_slots == 0 || self.pipeline == 0 || self.episode_ms == 0 {
            return Err("--run-slots, --pipeline and --episode-ms are at least 1".into());
        }
        for (conns, rate, name) in [
            (self.small_conns, self.small_rate, "--small-rate"),
            (self.slow_conns, self.slow_rate, "--slow-rate"),
        ] {
            if conns > 0 && (rate == 0 || rate > SEC) {
                return Err(format!("{name} is between 1 and 10^9"));
            }
        }
        if self.outside_rate > 0 && (self.outside_conns == 0 || self.outside_rate > SEC) {
            return Err("--outside-rate needs --outside-conns, and is at most 10^9".into());
        }
        if self.order == Order::O5 {
            let sizes = [
                (self.small_conns > 0, self.small_size),
                (self.slow_conns > 0, self.slow_size),
                (self.outside_rate > 0, self.outside_size),
                (self.stall_peers > 0, self.stall_size),
                (self.drainers > 0, self.drain_size),
                (true, self.large_size),
            ];
            for (used, len) in sizes {
                let (pool, slots) = self.slots(len, slot_size);
                if used && slots > capacity[pool] {
                    let name = if pool == MAIN { "large" } else { "small" };
                    return Err(format!(
                        "a {len} B reply needs {slots} slots of the {name} pool, which has {}",
                        capacity[pool]
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The admission pass of each order, apart from the event machinery so that
/// each order reads on its own and is tested directly.
///
/// A pass sees the FIFOs, the free slots, B and O3's latch, and returns the
/// waiters to admit, in the order they are admitted. It changes nothing; the
/// machinery applies the grants.
///
/// Terms, as `docs/send-admission-design.md` section 4 uses them: P is the
/// main pool's slots, F the free slots, H the slots the FIFO's head needs,
/// and B the slots held by sends admitted past a head, each counted until it
/// returns.
mod policy {
    use std::collections::{BTreeMap, BTreeSet, VecDeque};

    /// An admission order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
    pub enum Order {
        /// Strict FIFO, ringline's order: the head is admitted while it
        /// fits, and nothing else.
        O0,
        /// Small replies take slots at once or are refused, outside the
        /// FIFO; large replies wait in it under O0.
        O1,
        /// While the head does not fit, every eligible waiter behind it that
        /// fits in F, oldest first.
        O2,
        /// As O2 while F + B < H, latched off for the rest of the head's wait
        /// once F + B >= H has held.
        O3,
        /// As O3, onto connections with nothing admitted and unsettled.
        O4,
        /// As O3, onto connections whose kernel buffer has room for the whole
        /// reply now. An oracle ringline does not have.
        O4s,
        /// As O4, onto connections whose last settled send did not wait for
        /// room in the kernel buffer.
        O4w,
        /// Two pools, each with its own strict FIFO.
        O5,
        /// As O2 during the first `--o6-ms` of the head's wait, then as O0
        /// until the head changes.
        O6,
        /// As O2 while B plus the passing send's slots stays within
        /// min(R, P - H). No latch.
        O7,
        /// As O7, with O4w's condition on the connection.
        O7w,
    }

    /// The only pool, or O5's pool of large slots. The FIFO the experiment
    /// watches.
    pub const MAIN: usize = 0;
    /// O5's pool of small slots.
    pub const SMALL_POOL: usize = 1;

    impl Order {
        pub fn name(self) -> &'static str {
            match self {
                Order::O0 => "o0",
                Order::O1 => "o1",
                Order::O2 => "o2",
                Order::O3 => "o3",
                Order::O4 => "o4",
                Order::O4s => "o4s",
                Order::O4w => "o4w",
                Order::O5 => "o5",
                Order::O6 => "o6",
                Order::O7 => "o7",
                Order::O7w => "o7w",
            }
        }

        /// Whether sends admitted past a head count in B.
        pub fn marks(self) -> bool {
            matches!(
                self,
                Order::O3 | Order::O4 | Order::O4s | Order::O4w | Order::O7 | Order::O7w
            )
        }

        /// Whether a reply of this class skips the FIFO: under O1, small
        /// replies take slots at once or are refused, as `send` does.
        pub fn bypasses_fifo(self, small: bool) -> bool {
            self == Order::O1 && small
        }

        /// The pool a reply of `len` bytes takes slots from: under O5 the
        /// small pool when it fits one small slot, otherwise the main pool.
        pub fn pool(self, len: u64, small_slot_size: u64) -> usize {
            if self == Order::O5 && len <= small_slot_size {
                SMALL_POOL
            } else {
                MAIN
            }
        }
    }

    /// One waiter, as a pass sees it.
    #[derive(Clone, Debug)]
    pub struct Waiter {
        pub conn: u32,
        pub slots: u32,
        /// When it joined the FIFO, in ns.
        pub joined_at: u64,
        /// Arrival order across both FIFOs.
        pub seq: u64,
        /// Its connection has a reply admitted and not settled.
        pub conn_unsettled: bool,
        /// Its connection's last settled send waited for room in the kernel
        /// buffer: its bytes did not all go in when it was written.
        pub conn_waited: bool,
        /// Its connection's kernel buffer has room now for this whole reply
        /// and for what is queued ahead of it. Computed only for O4s, and
        /// true otherwise.
        pub conn_room: bool,
    }

    /// What a pass sees.
    pub struct State<'a> {
        pub now: u64,
        /// Waiters in arrival order, indexed by [`MAIN`] and [`SMALL_POOL`].
        pub fifos: [&'a [Waiter]; 2],
        /// F, per pool.
        pub free: [u32; 2],
        /// P, the main pool's slots.
        pub pool_slots: u32,
        /// B.
        pub marked: u32,
        /// O3's latch: F + B >= H has held at some moment of the current
        /// head's wait.
        pub latched: bool,
        /// O6's D, in ns.
        pub o6_ns: u64,
        /// O7's R, in slots.
        pub budget: u32,
    }

    /// A waiter to admit: its FIFO, its index there, and whether it is
    /// admitted past the head.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Grant {
        pub pool: usize,
        pub index: usize,
        pub passed: bool,
    }

    /// The waiters `order` admits now, in admission order.
    pub fn pass(order: Order, s: &State) -> Vec<Grant> {
        match order {
            Order::O0 | Order::O1 => o0(s),
            Order::O2 => o2(s),
            Order::O3 => o3(s),
            Order::O4 => o4(s),
            Order::O4s => o4s(s),
            Order::O4w => o4w(s),
            Order::O5 => o5(s),
            Order::O6 => o6(s),
            Order::O7 => o7(s),
            Order::O7w => o7w(s),
        }
    }

    /// O0: the head while F >= H; nothing else.
    fn o0(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        p.grants
    }

    /// O2: the head while it fits; then, while it does not, every eligible
    /// waiter behind it that fits in F, oldest first (first fit).
    fn o2(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        p.pass_head(|_, _| true);
        p.grants
    }

    /// O3: as O2 while F + B < H and the latch is off. Passing moves slots
    /// from F to B, so F + B changes only when slots return, and the
    /// condition holds or fails for the whole scan.
    fn o3(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        if p.below_head() {
            p.pass_head(|_, _| true);
        }
        p.grants
    }

    /// O4: as O3, onto connections with nothing admitted and unsettled.
    fn o4(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        if p.below_head() {
            p.pass_head(|p, w| p.idle(w));
        }
        p.grants
    }

    /// O4s: as O3, onto connections whose kernel buffer can take the whole
    /// reply now.
    fn o4s(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        if p.below_head() {
            p.pass_head(|p, w| w.conn_room && !p.granted_to(w.conn));
        }
        p.grants
    }

    /// O4w: as O4, onto connections whose last settled send did not wait
    /// for room.
    fn o4w(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        if p.below_head() {
            p.pass_head(|p, w| p.idle(w) && !w.conn_waited);
        }
        p.grants
    }

    /// O5: each pool admits its own head while it fits. A waiter whose
    /// connection has an earlier waiter in either pool is not a head (see
    /// [`Pass::head`]).
    fn o5(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        loop {
            let before = p.grants.len();
            p.admit_heads(SMALL_POOL);
            p.admit_heads(MAIN);
            if p.grants.len() == before {
                return p.grants;
            }
        }
    }

    /// O6: as O2 while the head has waited less than D since joining the
    /// FIFO, then as O0.
    fn o6(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        if let Some(h) = p.head(MAIN)
            && s.now.saturating_sub(s.fifos[MAIN][h].joined_at) < s.o6_ns
        {
            p.pass_head(|_, _| true);
        }
        p.grants
    }

    /// O7: as O2 while B plus the passing send's slots is at most
    /// min(R, P - H).
    fn o7(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        p.pass_head(|p, w| p.within_budget(w));
        p.grants
    }

    /// O7w: as O7, onto connections O4w would pass onto.
    fn o7w(s: &State) -> Vec<Grant> {
        let mut p = Pass::new(s);
        p.admit_heads(MAIN);
        p.pass_head(|p, w| p.within_budget(w) && p.idle(w) && !w.conn_waited);
        p.grants
    }

    /// One pass in progress: what it has granted, and F, B and the latch as
    /// the grants so far leave them.
    struct Pass<'a> {
        s: &'a State<'a>,
        taken: [Vec<bool>; 2],
        free: [u32; 2],
        marked: u32,
        latched: bool,
        granted: BTreeSet<u32>,
        grants: Vec<Grant>,
        /// Each FIFO's first waiter not yet granted.
        first: [usize; 2],
        /// The waiters not yet granted of each connection with more than one
        /// waiter, in either FIFO, oldest first: such a waiter is eligible
        /// when it is its connection's oldest. A connection with one waiter
        /// is not listed, and its waiter is always eligible.
        by_conn: BTreeMap<u32, VecDeque<u64>>,
    }

    impl<'a> Pass<'a> {
        fn new(s: &'a State<'a>) -> Self {
            let mut conns: Vec<u32> = s
                .fifos
                .iter()
                .flat_map(|f| f.iter().map(|w| w.conn))
                .collect();
            conns.sort_unstable();
            let mut by_conn: BTreeMap<u32, VecDeque<u64>> = BTreeMap::new();
            for pair in conns.windows(2) {
                if pair[0] == pair[1] {
                    by_conn.entry(pair[0]).or_default();
                }
            }
            if !by_conn.is_empty() {
                for w in s.fifos.iter().flat_map(|f| f.iter()) {
                    if let Some(seqs) = by_conn.get_mut(&w.conn) {
                        seqs.push_back(w.seq);
                    }
                }
                for seqs in by_conn.values_mut() {
                    seqs.make_contiguous().sort_unstable();
                }
            }
            Pass {
                s,
                taken: [vec![false; s.fifos[0].len()], vec![false; s.fifos[1].len()]],
                free: s.free,
                marked: s.marked,
                latched: s.latched,
                granted: BTreeSet::new(),
                grants: Vec::new(),
                first: [0, 0],
                by_conn,
            }
        }

        /// The first waiter of `pool` not yet granted whose connection has no
        /// earlier waiter left in either FIFO. In one FIFO that is the first
        /// waiter not granted; under O5 it skips a waiter held off by its
        /// connection's waiter in the other pool.
        fn head(&self, pool: usize) -> Option<usize> {
            (self.first[pool]..self.s.fifos[pool].len())
                .find(|&i| !self.taken[pool][i] && self.eligible(pool, i))
        }

        /// No earlier waiter of the same connection is left in either FIFO.
        fn eligible(&self, pool: usize, i: usize) -> bool {
            let w = &self.s.fifos[pool][i];
            self.by_conn
                .get(&w.conn)
                .is_none_or(|seqs| seqs.front() == Some(&w.seq))
        }

        /// Admit waiter `i` of `pool`, which is eligible.
        fn grant(&mut self, pool: usize, i: usize, passed: bool) {
            let s = self.s;
            let w = &s.fifos[pool][i];
            if let Some(seqs) = self.by_conn.get_mut(&w.conn) {
                let oldest = seqs.pop_front();
                debug_assert_eq!(oldest, Some(w.seq), "only an eligible waiter is granted");
            }
            self.taken[pool][i] = true;
            while self.taken[pool].get(self.first[pool]) == Some(&true) {
                self.first[pool] += 1;
            }
            self.free[pool] -= w.slots;
            if passed {
                self.marked += w.slots;
            }
            self.granted.insert(w.conn);
            self.grants.push(Grant {
                pool,
                index: i,
                passed,
            });
        }

        /// Admit `pool`'s head while it fits. Each admission changes the
        /// head, and a new head starts with the latch off;
        /// [`below_head`](Self::below_head) still compares F + B with its own H.
        fn admit_heads(&mut self, pool: usize) {
            while let Some(h) = self.head(pool) {
                if self.s.fifos[pool][h].slots > self.free[pool] {
                    return;
                }
                self.grant(pool, h, false);
                if pool == MAIN {
                    self.latched = false;
                }
            }
        }

        /// Admit, past the main FIFO's head, every eligible waiter behind it
        /// that fits in F and that `rule` allows, oldest first.
        fn pass_head(&mut self, rule: impl Fn(&Pass, &Waiter) -> bool) {
            let Some(h) = self.head(MAIN) else {
                return;
            };
            let s = self.s;
            for i in h + 1..s.fifos[MAIN].len() {
                let w = &s.fifos[MAIN][i];
                if !self.taken[MAIN][i]
                    && self.eligible(MAIN, i)
                    && w.slots <= self.free[MAIN]
                    && rule(self, w)
                {
                    self.grant(MAIN, i, true);
                }
            }
        }

        /// O3's condition: the latch is off and F + B < H.
        fn below_head(&self) -> bool {
            self.head(MAIN).is_some_and(|h| {
                !self.latched && self.free[MAIN] + self.marked < self.s.fifos[MAIN][h].slots
            })
        }

        /// O7's condition for `w`: B + its slots <= min(R, P - H).
        fn within_budget(&self, w: &Waiter) -> bool {
            let Some(h) = self.head(MAIN) else {
                return false;
            };
            let cap = self.s.budget.min(
                self.s
                    .pool_slots
                    .saturating_sub(self.s.fifos[MAIN][h].slots),
            );
            self.marked + w.slots <= cap
        }

        /// O4's condition: nothing admitted and unsettled on the connection,
        /// counting what this pass granted.
        fn idle(&self, w: &Waiter) -> bool {
            !w.conn_unsettled && !self.granted_to(w.conn)
        }

        fn granted_to(&self, conn: u32) -> bool {
            self.granted.contains(&conn)
        }
    }
}

/// splitmix64: the seeded source of the schedule phases.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in [0, n), from the high half of a 128-bit product.
    fn below(&mut self, n: u64) -> u64 {
        ((u128::from(self.next()) * u128::from(n)) >> 64) as u64
    }
}

/// What opened a connection, which sets its reader and how its replies are
/// counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Fast,
    Slow,
    Stall,
    Drain,
    Large,
    Outside,
}

impl Kind {
    const ALL: [Kind; 6] = [
        Kind::Fast,
        Kind::Slow,
        Kind::Stall,
        Kind::Drain,
        Kind::Large,
        Kind::Outside,
    ];

    /// The statistics group of a reply on this kind of connection.
    fn source(self) -> usize {
        match self {
            Kind::Fast => FAST,
            Kind::Slow => SLOW,
            _ => EPISODE,
        }
    }

    /// Its position in [`Kind::ALL`].
    fn index(self) -> usize {
        Kind::ALL
            .iter()
            .position(|&k| k == self)
            .expect("every kind is listed")
    }

    fn name(self) -> &'static str {
        match self {
            Kind::Fast => "fast",
            Kind::Slow => "slow",
            Kind::Stall => "stall",
            Kind::Drain => "drain",
            Kind::Large => "large",
            Kind::Outside => "outside",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Sent by the client, not yet read by the server.
    Requested,
    Waiting,
    Admitted,
    /// A reply sent in pieces, from its first piece's start until its last
    /// piece settles. The reply itself takes no slots; its pieces do.
    Streaming,
    Settled,
    /// Its connection ended first, or it was refused.
    Ended,
}

/// One request and its reply. A send outside the FIFO is one too, with no
/// request.
struct Reply {
    conn: u32,
    kind: Kind,
    len: u64,
    small: bool,
    pool: usize,
    slots: u32,
    scheduled_at: u64,
    in_window: bool,
    stage: Stage,
    joined_at: u64,
    seq: u64,
    admitted_at: u64,
    settle_deadline: u64,
    held: u32,
    /// Its slots count in B until they return.
    marked: bool,
    /// Bytes in the kernel buffer.
    entered: u64,
    /// Its bytes did not all go into the kernel buffer in one write.
    waited: bool,
    /// When its last byte went into the kernel buffer.
    settled_at: Option<u64>,
    /// When its last slot returned.
    released_at: Option<u64>,
    /// When the peer read its last byte; set at settlement.
    delivered_at: Option<u64>,
    /// For a piece: the reply it is part of, and its index there.
    parent: Option<u32>,
    piece: u32,
    /// For a reply sent in pieces: the pieces started.
    pieces: u32,
}

/// One slot of an admitted reply, in its connection's send queue.
struct Chunk {
    reply: u32,
    bytes: u64,
}

/// A kernel buffer's parameters, from the arguments for its kind of
/// connection.
struct Socket {
    kbuf: u64,
    rwnd: u64,
    seg: u64,
    overhead: u64,
    read_bps: u64,
}

struct Conn {
    kind: Kind,
    /// The client index for fast, slow and outside connections, the episode
    /// index otherwise.
    owner: usize,
    alive: bool,
    /// K, payload bytes in the send queue and the peer's receive buffer.
    kbuf: u64,
    /// The peer's receive window W, payload bytes of K.
    rwnd: u64,
    /// `sk_sndbuf`, K - W: the send queue's limit, in truesize.
    sndbuf: u64,
    /// The largest payload of a segment; 0: no segments.
    seg: u64,
    /// A segment's truesize beyond its payload.
    overhead: u64,
    /// The send queue's truesize at or below which the socket reports
    /// `POLLOUT`: a send that filled the buffer resumes, and a gated piece
    /// goes on.
    writable: u64,
    read_bps: u64,
    /// Bytes ever written into the kernel buffer.
    written: u64,
    /// The reader reads `read_bps` from `read_base` at `read_t` until it has
    /// read everything written. The line is reset only when a write finds
    /// the buffer empty, so no rounding accumulates.
    read_base: u64,
    read_t: u64,
    /// End offsets of the segments not wholly out of the send queue, oldest
    /// first; the last one can be part full. Empty while `seg` is 0.
    segs: VecDeque<u64>,
    /// Where the last segment starts.
    tail_start: u64,
    /// A send filled the buffer and waits for `writable` or the backstop.
    blocked: bool,
    /// Names the current wait, so an earlier wait's `Writable` is ignored.
    token: u64,
    queue: VecDeque<Chunk>,
    /// The run in flight, the chunk the next byte goes to, and its bytes
    /// already written.
    run: Vec<Chunk>,
    run_cursor: usize,
    run_done: u64,
    run_left: u64,
    /// Admitted bytes not yet in the kernel buffer.
    pending: u64,
    requests: VecDeque<u32>,
    /// Its replies in a FIFO.
    waiting: u32,
    /// Its admitted, unsettled replies, oldest first.
    unsettled: VecDeque<u32>,
    last_settled_at: u64,
    /// The last settled reply's `waited` (O4w).
    last_waited: bool,
    /// The reply being sent in pieces. The connection reads no request
    /// until its last piece is admitted.
    streaming: Option<u32>,
    /// A piece waits for `POLLOUT`; the value names the wait, so an earlier
    /// wait's events are ignored.
    gate: Option<u64>,
    gate_token: u64,
    /// The replies of an episode's connection that have settled, so that an
    /// end before their last byte is read undoes their delivery.
    settled: Vec<u32>,
    /// When the connection ended.
    ended_at: Option<u64>,
}

impl Conn {
    /// Bytes the reader has read by `t`.
    fn read_at(&self, t: u64) -> u64 {
        let n =
            u128::from(t.saturating_sub(self.read_t)) * u128::from(self.read_bps) / u128::from(SEC);
        (u128::from(self.read_base) + n).min(u128::from(self.written)) as u64
    }

    /// k at `t`.
    fn occupancy(&self, t: u64) -> u64 {
        self.written - self.read_at(t)
    }

    /// When the reader reaches byte offset `pos`; `read_bps` is above 0 and
    /// `pos` is past the line's base.
    fn time_reading(&self, pos: u64) -> u64 {
        let ns = (u128::from(pos - self.read_base) * u128::from(SEC))
            .div_ceil(u128::from(self.read_bps));
        self.read_t + ns.min(u128::from(u64::MAX - self.read_t)) as u64
    }

    /// The stream offset below which written bytes have left the send queue
    /// at `t`: what the reader has read, and the peer's receive window.
    fn ack_limit(&self, t: u64) -> u64 {
        self.read_at(t) + self.rwnd
    }

    /// The send queue's truesize at `t` (`sk_wmem_queued`).
    fn queued(&self, t: u64) -> u64 {
        let acked = self.written.min(self.ack_limit(t));
        let gone = self.segs.partition_point(|&end| end <= acked);
        self.written - acked + self.overhead * (self.segs.len() - gone) as u64
    }

    /// Drop the segments wholly below `acked`.
    fn trim(&mut self, acked: u64) {
        while self.segs.front().is_some_and(|&end| end <= acked) {
            self.segs.pop_front();
        }
    }

    /// The bytes of a `sendmsg` of `left` bytes at `t` that go into the send
    /// queue, as `tcp_sendmsg_locked` takes them: without segments, up to the
    /// buffer's limit; with them, the last segment topped up to `seg`
    /// unchecked, then whole segments while the queue's truesize is below
    /// `sndbuf`. Records the segments; the caller advances `written`.
    fn take(&mut self, t: u64, left: u64) -> u64 {
        let ack = self.ack_limit(t);
        if self.seg == 0 {
            return (ack + self.sndbuf).saturating_sub(self.written).min(left);
        }
        let mut w = self.written;
        let mut n = 0;
        self.trim(w.min(ack));
        if let Some(end) = self.segs.back_mut() {
            let unsent = *end - self.tail_start.max(w.min(ack));
            if unsent < self.seg {
                let more = (self.seg - unsent).min(left);
                *end += more;
                w += more;
                n += more;
            }
        }
        while n < left {
            self.trim(w.min(ack));
            let q = w - w.min(ack) + self.overhead * self.segs.len() as u64;
            if q >= self.sndbuf {
                break;
            }
            let more = self.seg.min(left - n);
            self.tail_start = w;
            w += more;
            n += more;
            self.segs.push_back(w);
        }
        self.trim(w.min(ack));
        n
    }

    /// When the send queue's truesize falls to `writable`: `t` if it is
    /// there now, and `None` for a reader that does not read.
    fn writable_at(&self, t: u64) -> Option<u64> {
        let acked = self.written.min(self.ack_limit(t));
        if self.queued(t) <= self.writable {
            return Some(t);
        }
        if self.read_bps == 0 {
            return None;
        }
        // The smallest acknowledged offset A at which the queue is at most
        // `writable`. While A is inside segment j of m left, the queue is
        // written - A plus the overhead of segments j to m.
        let gone = self.segs.partition_point(|&end| end <= acked);
        let mut live = (self.segs.len() - gone) as u64;
        let mut from = acked;
        let mut target = None;
        for &end in self.segs.iter().skip(gone) {
            let need = (self.written + self.overhead * live).saturating_sub(self.writable);
            if need.max(from) < end {
                target = Some(need.max(from));
                break;
            }
            from = end;
            live -= 1;
        }
        let a = target.unwrap_or_else(|| self.written.saturating_sub(self.writable).max(from));
        let pos = a.saturating_sub(self.rwnd);
        Some(if pos <= self.read_at(t) {
            t
        } else {
            self.time_reading(pos)
        })
    }
}

/// An open-loop source of requests, or of sends outside the FIFO.
struct Client {
    kind: Kind,
    conn: u32,
    interval: u64,
    size: u64,
    /// Requests sent and not yet read back, oldest first.
    pending: VecDeque<u32>,
    offered: u64,
    lost: u64,
    /// Delivered requests' latencies, scheduled send to last byte read.
    latencies: Vec<u64>,
    reconnects: u64,
    /// Outside sends: taken, and refused for want of slots.
    sent: u64,
    refused: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    NotRequested,
    Waiting,
    Admitted,
    AdmitTimeout,
    SettleAbort,
    RoomTimeout,
    Failed,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Outcome::NotRequested => "not_requested",
            Outcome::Waiting => "waiting",
            Outcome::Admitted => "admitted",
            Outcome::AdmitTimeout => "admit_timeout",
            Outcome::SettleAbort => "settle_abort",
            Outcome::RoomTimeout => "room_timeout",
            Outcome::Failed => "failed",
        }
    }
}

/// One episode and what its head met.
struct Episode {
    start: u64,
    /// Its stalled peers and drainers.
    peers: Vec<u32>,
    head: Option<u32>,
    requested_at: u64,
    /// When the head was admitted, whatever happened to it after.
    admitted_at: Option<u64>,
    outcome: Outcome,
    /// `Sim::area` and the time when the head joined the FIFO.
    area_at_join: [u128; HELD_COUNTERS],
    /// `Sim::held` time-averaged over the head's wait: L, and L unsettled.
    held_during_wait: Option<[f64; HELD_COUNTERS]>,
    /// The largest B during the head's wait.
    max_marked: u32,
    /// The first moment of the head's wait at which F + B >= its H.
    covered_at: Option<u64>,
    /// Sends admitted ahead of the head while it waited, from behind it.
    passed: Vec<u32>,
    /// The waiter whose wait is the head's: the head, or its first piece.
    wait: Option<u32>,
    /// The fewest free main-pool slots from the head's request to its last
    /// byte read, or to its end: at every change, and in the samples.
    min_free: Option<u32>,
    min_free_sampled: Option<u32>,
}

/// Counters and delays for one reply class and source.
#[derive(Default)]
struct Stats {
    replies: u64,
    admitted: u64,
    passed: u64,
    /// Scheduled send to admission, ns.
    scheduled_delay: Vec<u64>,
    /// FIFO join to admission, ns.
    join_delay: Vec<u64>,
    admit_timeouts: u64,
    settle_aborts: u64,
    room_timeouts: u64,
    refused: u64,
    failed: u64,
    dropped: u64,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.replies += o.replies;
        self.admitted += o.admitted;
        self.passed += o.passed;
        self.scheduled_delay.extend_from_slice(&o.scheduled_delay);
        self.join_delay.extend_from_slice(&o.join_delay);
        self.admit_timeouts += o.admit_timeouts;
        self.settle_aborts += o.settle_aborts;
        self.room_timeouts += o.room_timeouts;
        self.refused += o.refused;
        self.failed += o.failed;
        self.dropped += o.dropped;
    }

    fn report(&self) -> Value {
        json!({
            "replies": self.replies,
            "admitted": self.admitted,
            "passed": self.passed,
            "scheduled_to_admission_us": percentiles(&self.scheduled_delay),
            "join_to_admission_us": percentiles(&self.join_delay),
            "admit_timeouts": self.admit_timeouts,
            "settle_aborts": self.settle_aborts,
            "room_timeouts": self.room_timeouts,
            "refused": self.refused,
            "failed": self.failed,
            "dropped": self.dropped,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    /// A client's next scheduled request or outside send.
    Send(usize),
    EpisodeStart(usize),
    /// Stalled peer i of the episode asks (`--stall-gap-us` above 0).
    StallRequest(usize, usize),
    LargeRequest(usize),
    /// The stalled peers and drainers close.
    EpisodeClose(usize),
    AdmitDeadline(u32),
    SettleDeadline(u32),
    /// A blocked connection's buffer has drained to its writable mark.
    Writable(u32, u64),
    Backstop,
    /// A gated piece's socket may have drained to its writable mark.
    GateOpen(u32, u64),
    /// A gated piece has waited `--settle-ms` for room.
    RoomDeadline(u32, u64),
    /// Sample the free slots for the heads in progress.
    Sample,
}

/// An event and when it runs. `BinaryHeap` pops the largest, so the order
/// is reversed: earliest time first and, at one time, first scheduled first.
struct Scheduled {
    at: u64,
    seq: u64,
    event: Event,
}

impl PartialEq for Scheduled {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.seq) == (o.at, o.seq)
    }
}

impl Eq for Scheduled {}

impl PartialOrd for Scheduled {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

impl Ord for Scheduled {
    fn cmp(&self, o: &Self) -> Ordering {
        (o.at, o.seq).cmp(&(self.at, self.seq))
    }
}

/// Why a connection ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    AdmitTimeout,
    SettleAbort,
    /// A gated piece waited `--settle-ms` for room in the socket.
    RoomTimeout,
    Refused,
    /// The reply can never be admitted: it needs more slots than its pool
    /// has (`bounded_send_slots`' `InvalidInput`).
    Failed,
    /// The client closed it.
    PeerClosed,
}

impl End {
    const ALL: [End; 6] = [
        End::AdmitTimeout,
        End::SettleAbort,
        End::RoomTimeout,
        End::Refused,
        End::Failed,
        End::PeerClosed,
    ];

    /// The name of the cause in the output. A peer close is counted only
    /// when the server was still sending to the peer, so it is a reset.
    fn name(self) -> &'static str {
        match self {
            End::AdmitTimeout => "admit_timeout",
            End::SettleAbort => "settle_timeout",
            End::RoomTimeout => "room_timeout",
            End::Refused => "refused",
            End::Failed => "failed",
            End::PeerClosed => "peer_reset",
        }
    }
}

struct Sim {
    a: Args,
    capacity: [u32; 2],
    slot_size: [u64; 2],
    budget: u32,
    o6_ns: u64,
    window: (u64, u64),
    end: u64,

    now: u64,
    seq: u64,
    events: BinaryHeap<Scheduled>,
    events_run: u64,

    conns: Vec<Conn>,
    replies: Vec<Reply>,
    clients: Vec<Client>,
    episodes: Vec<Episode>,

    fifos: [VecDeque<u32>; 2],
    waiter_seq: u64,
    free: [u32; 2],
    /// B.
    marked: u32,
    /// The main FIFO's head, and O3's latch for it.
    head: Option<u32>,
    latched: bool,
    /// Episodes whose head is in the FIFO.
    waiting_heads: Vec<usize>,
    /// Replies holding slots.
    holding: BTreeSet<u32>,
    /// The counters [`HELD_FAST`] to [`UNSETTLED_SLOW`] name, and their
    /// integrals over time (slot-ns) up to `area_t`. A small reply counts in
    /// its unsettled counter at its whole `slots` from admission until it
    /// settles or its connection ends, as admission-server counts it: it
    /// does not see the slots a settled reply still holds in a run that has
    /// not finished.
    held: [u64; HELD_COUNTERS],
    area: [u128; HELD_COUNTERS],
    area_t: u64,

    blocked: BTreeSet<u32>,
    backstop_at: Option<u64>,
    to_pump: BTreeSet<u32>,
    to_serve: BTreeSet<u32>,
    /// Connections whose reply's next piece is due.
    to_stream: BTreeSet<u32>,

    /// Indexed by class, then by source.
    stats: [[Stats; 3]; 2],
    /// Episodes whose head was requested and has not ended or been read.
    open_heads: Vec<usize>,
    /// Connections ended in the window, by cause (`End::ALL`) and kind
    /// (`Kind::ALL`). A peer close counts only while the server was sending.
    ends: [[u64; 6]; 6],
    /// Pieces that waited at the gate, by kind.
    gate_waits: [u64; 6],
}

impl Sim {
    fn new(a: &Args) -> Sim {
        let (capacity, slot_size) = a.pools().expect("checked");
        let window = (a.warmup * SEC, (a.warmup + a.duration) * SEC);
        let mut sim = Sim {
            a: a.clone(),
            capacity,
            slot_size,
            budget: a.budget(capacity, slot_size),
            o6_ns: a.o6_ns(),
            window,
            end: window.1 + a.admit_ms * MS + 2 * SEC,
            now: 0,
            seq: 0,
            events: BinaryHeap::new(),
            events_run: 0,
            conns: Vec::new(),
            replies: Vec::new(),
            clients: Vec::new(),
            episodes: Vec::new(),
            fifos: [VecDeque::new(), VecDeque::new()],
            waiter_seq: 0,
            free: capacity,
            marked: 0,
            head: None,
            latched: false,
            waiting_heads: Vec::new(),
            holding: BTreeSet::new(),
            held: [0; HELD_COUNTERS],
            area: [0; HELD_COUNTERS],
            area_t: 0,
            blocked: BTreeSet::new(),
            backstop_at: None,
            to_pump: BTreeSet::new(),
            to_serve: BTreeSet::new(),
            to_stream: BTreeSet::new(),
            stats: Default::default(),
            open_heads: Vec::new(),
            ends: [[0; 6]; 6],
            gate_waits: [0; 6],
        };
        let mut rng = SplitMix64(a.seed);
        let groups = [
            (Kind::Fast, a.small_conns, a.small_rate, a.small_size),
            (
                Kind::Slow,
                a.slow_conns,
                a.slow_rate * a.slow_conns as u64,
                a.slow_size,
            ),
            (
                Kind::Outside,
                a.outside_conns,
                a.outside_rate,
                a.outside_size,
            ),
        ];
        for (kind, conns, rate, size) in groups {
            if conns == 0 || rate == 0 {
                continue;
            }
            // admission-load: the interval is the total rate's, times the
            // connections, and connection i starts i / conns of it in.
            let interval = SEC * conns as u64 / rate;
            for i in 0..conns {
                let mut first = interval * i as u64 / conns as u64;
                if a.seed > 0 {
                    first += rng.below(interval);
                }
                let index = sim.clients.len();
                let conn = sim.open(kind, index);
                sim.clients.push(Client {
                    kind,
                    conn,
                    interval,
                    size,
                    pending: VecDeque::new(),
                    offered: 0,
                    lost: 0,
                    latencies: Vec::new(),
                    reconnects: 0,
                    sent: 0,
                    refused: 0,
                });
                if first < window.1 {
                    sim.schedule(first, Event::Send(index));
                }
            }
        }
        let mut at = window.0;
        while at + a.episode_ms * MS <= window.1 {
            sim.schedule(at, Event::EpisodeStart(sim.episodes.len()));
            sim.episodes.push(Episode {
                start: at,
                peers: Vec::new(),
                head: None,
                requested_at: 0,
                admitted_at: None,
                outcome: Outcome::NotRequested,
                area_at_join: [0; HELD_COUNTERS],
                held_during_wait: None,
                max_marked: 0,
                covered_at: None,
                passed: Vec::new(),
                wait: None,
                min_free: None,
                min_free_sampled: None,
            });
            at += a.episode_ms * MS;
        }
        if a.sample_ms > 0 {
            sim.schedule(0, Event::Sample);
        }
        sim
    }

    fn schedule(&mut self, at: u64, event: Event) {
        self.seq += 1;
        self.events.push(Scheduled {
            at,
            seq: self.seq,
            event,
        });
    }

    /// Run every event up to the end of the drain.
    fn run(&mut self) {
        while self.step() {}
        self.finish();
    }

    /// Run the next event and everything it sets off at the same instant.
    /// False once no event is due before the end.
    fn step(&mut self) -> bool {
        let Some(ev) = self.events.pop() else {
            return false;
        };
        if ev.at > self.end {
            return false;
        }
        self.now = ev.at;
        self.handle(ev.event);
        self.quiesce();
        self.events_run += 1;
        true
    }

    fn open(&mut self, kind: Kind, owner: usize) -> u32 {
        let s = self.a.socket(kind);
        let sndbuf = s.kbuf - s.rwnd;
        self.conns.push(Conn {
            kind,
            owner,
            alive: true,
            kbuf: s.kbuf,
            rwnd: s.rwnd,
            sndbuf,
            seg: s.seg,
            overhead: s.overhead,
            writable: (sndbuf as f64 * self.a.writable) as u64,
            read_bps: s.read_bps,
            written: 0,
            read_base: 0,
            read_t: self.now,
            segs: VecDeque::new(),
            tail_start: 0,
            blocked: false,
            token: 0,
            queue: VecDeque::new(),
            run: Vec::new(),
            run_cursor: 0,
            run_done: 0,
            run_left: 0,
            pending: 0,
            requests: VecDeque::new(),
            waiting: 0,
            unsettled: VecDeque::new(),
            last_settled_at: 0,
            last_waited: false,
            streaming: None,
            gate: None,
            gate_token: 0,
            settled: Vec::new(),
            ended_at: None,
        });
        (self.conns.len() - 1) as u32
    }

    /// A reply of `len` bytes on `conn`, scheduled now.
    fn new_reply(&mut self, conn: u32, len: u64) -> u32 {
        let len = len.max(8);
        let (pool, slots) = self.a.slots(len, self.slot_size);
        self.replies.push(Reply {
            conn,
            kind: self.conns[conn as usize].kind,
            len,
            small: len <= self.a.small_max,
            pool,
            slots,
            scheduled_at: self.now,
            in_window: self.now >= self.window.0 && self.now < self.window.1,
            stage: Stage::Requested,
            joined_at: 0,
            seq: 0,
            admitted_at: 0,
            settle_deadline: 0,
            held: 0,
            marked: false,
            entered: 0,
            waited: false,
            settled_at: None,
            released_at: None,
            delivered_at: None,
            parent: None,
            piece: 0,
            pieces: 0,
        });
        (self.replies.len() - 1) as u32
    }

    /// The reply `r` is part of: its parent for a piece, otherwise itself.
    fn logical(&self, r: u32) -> u32 {
        self.replies[r as usize].parent.unwrap_or(r)
    }

    /// Whether `r` is the first send of its reply: a whole reply, or a first
    /// piece.
    fn first_send(&self, r: u32) -> bool {
        self.replies[r as usize].piece == 0
    }

    /// Whether `r` is the last send of its reply.
    fn last_send(&self, r: u32) -> bool {
        let reply = &self.replies[r as usize];
        reply
            .parent
            .is_none_or(|p| reply.piece + 1 == self.piece_count(p))
    }

    /// The pieces reply `r` is sent in; 1 for a reply sent whole.
    fn piece_count(&self, r: u32) -> u32 {
        let reply = &self.replies[r as usize];
        if self.pieced(r) {
            reply.len.div_ceil(self.a.stream_piece) as u32
        } else {
            1
        }
    }

    /// Whether reply `r` is sent in pieces.
    fn pieced(&self, r: u32) -> bool {
        let reply = &self.replies[r as usize];
        reply.parent.is_none()
            && self.a.stream_piece > 0
            && !reply.small
            && reply.kind != Kind::Outside
            && reply.len > self.a.stream_piece
    }

    /// The client sends a request on `conn`.
    fn request(&mut self, conn: u32, len: u64) -> u32 {
        let r = self.new_reply(conn, len);
        self.conns[conn as usize].requests.push_back(r);
        self.to_serve.insert(conn);
        r
    }

    fn stats(&mut self, r: u32) -> &mut Stats {
        let reply = &self.replies[r as usize];
        let class = if reply.small { SMALL } else { LARGE };
        &mut self.stats[class][reply.kind.source()]
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::Send(i) => self.send(i),
            Event::EpisodeStart(e) => {
                let gap = self.a.stall_gap_us * 1000;
                if gap == 0 {
                    for _ in 0..self.a.stall_peers {
                        self.stall_request(e);
                    }
                }
                for _ in 0..self.a.drainers {
                    let c = self.open(Kind::Drain, e);
                    self.request(c, self.a.drain_size);
                    self.episodes[e].peers.push(c);
                }
                if gap > 0 {
                    for i in 0..self.a.stall_peers {
                        self.schedule(self.now + i as u64 * gap, Event::StallRequest(e, i));
                    }
                }
                let stalls = self.a.stall_peers as u64 * gap;
                self.schedule(
                    self.now + stalls + self.a.large_delay_ms * MS,
                    Event::LargeRequest(e),
                );
                self.schedule(
                    self.now + self.a.episode_ms.saturating_sub(100) * MS,
                    Event::EpisodeClose(e),
                );
            }
            Event::StallRequest(e, _) => self.stall_request(e),
            Event::LargeRequest(e) => {
                let c = self.open(Kind::Large, e);
                let r = self.request(c, self.a.large_size);
                let ep = &mut self.episodes[e];
                ep.head = Some(r);
                ep.requested_at = self.now;
                ep.outcome = Outcome::Waiting;
                ep.min_free = Some(self.free[MAIN]);
                ep.min_free_sampled = None;
                self.open_heads.push(e);
            }
            Event::EpisodeClose(e) => {
                for c in self.episodes[e].peers.clone() {
                    self.end_conn(c, None, End::PeerClosed);
                }
            }
            Event::AdmitDeadline(r) => {
                if self.replies[r as usize].stage == Stage::Waiting {
                    let c = self.replies[r as usize].conn;
                    self.end_conn(c, Some(r), End::AdmitTimeout);
                }
            }
            Event::SettleDeadline(r) => {
                let reply = &self.replies[r as usize];
                if reply.stage == Stage::Admitted && reply.settle_deadline == self.now {
                    let c = reply.conn;
                    self.end_conn(c, Some(r), End::SettleAbort);
                }
            }
            Event::Writable(c, token) => {
                let conn = &mut self.conns[c as usize];
                if conn.alive && conn.blocked && conn.token == token {
                    conn.blocked = false;
                    conn.token += 1;
                    self.blocked.remove(&c);
                    self.to_pump.insert(c);
                }
            }
            Event::Backstop => {
                self.backstop_at = None;
                for c in std::mem::take(&mut self.blocked) {
                    let conn = &mut self.conns[c as usize];
                    conn.blocked = false;
                    conn.token += 1;
                    self.to_pump.insert(c);
                }
            }
            Event::GateOpen(c, token) => {
                let conn = &self.conns[c as usize];
                if conn.alive && conn.gate == Some(token) {
                    match conn.writable_at(self.now) {
                        Some(at) if at <= self.now => {
                            self.conns[c as usize].gate = None;
                            self.start_piece(c);
                        }
                        Some(at) => self.schedule(at, Event::GateOpen(c, token)),
                        None => {}
                    }
                }
            }
            Event::RoomDeadline(c, token) => {
                let conn = &self.conns[c as usize];
                if conn.alive && conn.gate == Some(token) {
                    let r = conn.streaming;
                    self.end_conn(c, r, End::RoomTimeout);
                }
            }
            Event::Sample => {
                self.track_free(true);
                let next = self.now + self.a.sample_ms * MS;
                if next <= self.end {
                    self.schedule(next, Event::Sample);
                }
            }
        }
    }

    /// One stalled peer of episode `e` connects and asks.
    fn stall_request(&mut self, e: usize) {
        let c = self.open(Kind::Stall, e);
        self.request(c, self.a.stall_size);
        self.episodes[e].peers.push(c);
    }

    /// Bring each open head's fewest free slots up to now, in its samples
    /// too if `sample`, and drop the heads that have ended or been read.
    fn track_free(&mut self, sample: bool) {
        let free = self.free[MAIN];
        let now = self.now;
        let Sim {
            open_heads,
            episodes,
            replies,
            ..
        } = self;
        open_heads.retain(|&e| {
            let ep = &mut episodes[e];
            let head = &replies[ep.head.expect("an open head was requested") as usize];
            if head.stage == Stage::Ended || head.delivered_at.is_some_and(|d| d < now) {
                return false;
            }
            ep.min_free = ep.min_free.min(Some(free));
            if sample {
                ep.min_free_sampled = Some(ep.min_free_sampled.map_or(free, |m| m.min(free)));
            }
            true
        });
    }

    /// A client's scheduled request or outside send.
    fn send(&mut self, i: usize) {
        self.collect_delivered(i);
        let (conn, size, kind) = {
            let c = &self.clients[i];
            (c.conn, c.size, c.kind)
        };
        let in_window = self.now >= self.window.0 && self.now < self.window.1;
        if kind == Kind::Outside {
            let r = self.new_reply(conn, size);
            let (pool, slots) = (
                self.replies[r as usize].pool,
                self.replies[r as usize].slots,
            );
            let client = &mut self.clients[i];
            let fits = self.free[pool] >= slots;
            if in_window {
                client.offered += 1;
                client.sent += u64::from(fits);
                client.refused += u64::from(!fits);
            }
            if fits {
                self.replies[r as usize].joined_at = self.now;
                self.admit(r, false);
            } else {
                self.replies[r as usize].stage = Stage::Ended;
            }
        } else {
            let r = self.request(conn, size);
            let client = &mut self.clients[i];
            if in_window {
                client.offered += 1;
            }
            client.pending.push_back(r);
        }
        let next = self.now + self.clients[i].interval;
        if next < self.window.1 {
            self.schedule(next, Event::Send(i));
        }
    }

    /// Record the client's replies read by now.
    fn collect_delivered(&mut self, i: usize) {
        while let Some(&r) = self.clients[i].pending.front() {
            let reply = &self.replies[r as usize];
            let Some(at) = reply.delivered_at.filter(|&d| d <= self.now) else {
                return;
            };
            let (in_window, latency) = (reply.in_window, at - reply.scheduled_at);
            let client = &mut self.clients[i];
            client.pending.pop_front();
            if in_window {
                client.latencies.push(latency);
            }
        }
    }

    /// Everything the client has not read by now is lost.
    fn lose_pending(&mut self, i: usize) {
        self.collect_delivered(i);
        for r in std::mem::take(&mut self.clients[i].pending) {
            let reply = &self.replies[r as usize];
            if reply.in_window {
                self.clients[i].lost += 1;
            }
        }
    }

    /// Process what the current event set off until nothing changes: write
    /// what the buffers take, read requests the server is free to read, and
    /// run the admission pass.
    fn quiesce(&mut self) {
        loop {
            let mut busy = false;
            while let Some(c) = self.to_pump.pop_first() {
                self.pump(c);
                busy = true;
            }
            while let Some(c) = self.to_serve.pop_first() {
                self.serve(c);
                busy = true;
            }
            while let Some(c) = self.to_stream.pop_first() {
                self.next_piece(c);
                busy = true;
            }
            if self.admission_pass() {
                busy = true;
            }
            if !busy {
                return;
            }
        }
    }

    /// The connection task reads requests while it has no waiter, sends no
    /// reply in pieces, and has fewer than `--pipeline` unsettled replies.
    fn serve(&mut self, c: u32) {
        loop {
            let conn = &self.conns[c as usize];
            if !conn.alive
                || conn.waiting > 0
                || conn.streaming.is_some()
                || conn.unsettled.len() >= self.a.pipeline
            {
                return;
            }
            let Some(&r) = conn.requests.front() else {
                return;
            };
            self.conns[c as usize].requests.pop_front();
            if self.pieced(r) {
                let (pool, slots) = self.a.slots(self.a.stream_piece, self.slot_size);
                if slots > self.capacity[pool] {
                    self.end_conn(c, Some(r), End::Failed);
                    return;
                }
                let reply = &mut self.replies[r as usize];
                reply.joined_at = self.now;
                reply.stage = Stage::Streaming;
                self.conns[c as usize].streaming = Some(r);
                self.next_piece(c);
                continue;
            }
            let reply = &mut self.replies[r as usize];
            reply.joined_at = self.now;
            let (pool, slots, small) = (reply.pool, reply.slots, reply.small);
            if slots > self.capacity[pool] {
                self.end_conn(c, Some(r), End::Failed);
                return;
            }
            if self.a.order.bypasses_fifo(small) {
                if self.free[pool] < slots {
                    self.end_conn(c, Some(r), End::Refused);
                    return;
                }
                self.admit(r, false);
                continue;
            }
            self.join(r);
        }
    }

    /// The streaming reply on `c` starts its next piece: with the gate, once
    /// the socket reports `POLLOUT`, waiting at most `--settle-ms`.
    fn next_piece(&mut self, c: u32) {
        let now = self.now;
        let conn = &mut self.conns[c as usize];
        if !conn.alive || conn.streaming.is_none() {
            return;
        }
        if self.a.stream_gate {
            match conn.writable_at(now) {
                Some(at) if at <= now => {}
                at => {
                    conn.gate_token += 1;
                    let token = conn.gate_token;
                    conn.gate = Some(token);
                    self.gate_waits[conn.kind.index()] += 1;
                    if let Some(at) = at {
                        self.schedule(at, Event::GateOpen(c, token));
                    }
                    self.schedule(now + self.a.settle_ms * MS, Event::RoomDeadline(c, token));
                    return;
                }
            }
        }
        self.start_piece(c);
    }

    /// The next piece of the streaming reply on `c` joins the FIFO.
    fn start_piece(&mut self, c: u32) {
        let l = self.conns[c as usize]
            .streaming
            .expect("a piece belongs to a streaming reply");
        let p = self.a.stream_piece;
        let logical = &mut self.replies[l as usize];
        let i = logical.pieces;
        logical.pieces += 1;
        let len = p.min(logical.len - u64::from(i) * p);
        let (scheduled_at, in_window) = (logical.scheduled_at, logical.in_window);
        let r = self.new_reply(c, len);
        let (pool, slots) = self.a.slots(len, self.slot_size);
        let piece = &mut self.replies[r as usize];
        piece.len = len;
        piece.small = false;
        piece.pool = pool;
        piece.slots = slots;
        piece.scheduled_at = scheduled_at;
        piece.in_window = in_window;
        piece.parent = Some(l);
        piece.piece = i;
        piece.joined_at = self.now;
        self.join(r);
    }

    fn join(&mut self, r: u32) {
        self.waiter_seq += 1;
        let reply = &mut self.replies[r as usize];
        reply.stage = Stage::Waiting;
        reply.seq = self.waiter_seq;
        let (pool, conn, kind) = (reply.pool, reply.conn, reply.kind);
        self.conns[conn as usize].waiting += 1;
        self.fifos[pool].push_back(r);
        self.schedule(self.now + self.a.admit_ms * MS, Event::AdmitDeadline(r));
        if kind == Kind::Large {
            let e = self.conns[conn as usize].owner;
            if self.episodes[e].head == Some(self.logical(r)) && self.first_send(r) {
                self.advance_area();
                let ep = &mut self.episodes[e];
                ep.area_at_join = self.area;
                ep.max_marked = self.marked;
                ep.wait = Some(r);
                self.waiting_heads.push(e);
            }
        }
        self.note_head();
    }

    fn fifo_remove(&mut self, r: u32) {
        let pool = self.replies[r as usize].pool;
        let at = self.fifos[pool]
            .iter()
            .position(|&w| w == r)
            .expect("a waiter is in its FIFO");
        self.fifos[pool].remove(at);
        self.conns[self.replies[r as usize].conn as usize].waiting -= 1;
        self.leave_wait(r);
        self.note_head();
    }

    /// If `r` is an episode head's waiter, the head's wait ends now.
    fn leave_wait(&mut self, r: u32) {
        let Some(pos) = self
            .waiting_heads
            .iter()
            .position(|&e| self.episodes[e].wait == Some(r))
        else {
            return;
        };
        let e = self.waiting_heads.remove(pos);
        self.advance_area();
        let ep = &mut self.episodes[e];
        let joined = self.replies[r as usize].joined_at;
        let span = self.now - joined;
        ep.held_during_wait = Some(std::array::from_fn(|i| {
            if span == 0 {
                self.held[i] as f64
            } else {
                (self.area[i] - ep.area_at_join[i]) as f64 / span as f64
            }
        }));
    }

    /// The main FIFO's head may have changed; a new head starts with the
    /// latch off, and latches at once if F + B already covers it.
    fn note_head(&mut self) {
        let head = self.fifos[MAIN].front().copied();
        if head != self.head {
            self.head = head;
            self.latched = false;
        }
        self.watch();
    }

    /// Record a moment at which F + B >= H: O3's latch for the FIFO's head,
    /// and, for each episode head waiting, the first such moment and the
    /// largest B.
    fn watch(&mut self) {
        let covered = self.free[MAIN] + self.marked;
        if let Some(h) = self.head
            && covered >= self.replies[h as usize].slots
        {
            self.latched = true;
        }
        for &e in &self.waiting_heads {
            let ep = &mut self.episodes[e];
            let h = ep.wait.expect("a waiting head has a waiter");
            ep.max_marked = ep.max_marked.max(self.marked);
            if ep.covered_at.is_none() && covered >= self.replies[h as usize].slots {
                ep.covered_at = Some(self.now);
            }
        }
    }

    /// Bring the held-slot integrals up to now.
    fn advance_area(&mut self) {
        let dt = u128::from(self.now - self.area_t);
        for i in 0..HELD_COUNTERS {
            self.area[i] += u128::from(self.held[i]) * dt;
        }
        self.area_t = self.now;
    }

    /// Which `held` counter a reply's main-pool slots count in.
    fn held_index(&self, r: u32) -> Option<usize> {
        let reply = &self.replies[r as usize];
        if reply.pool != MAIN {
            return None;
        }
        match reply.kind {
            Kind::Fast if reply.small => Some(HELD_FAST),
            Kind::Slow if reply.small => Some(HELD_SLOW),
            Kind::Outside => Some(HELD_OUTSIDE),
            _ => None,
        }
    }

    /// Which unsettled counter a reply counts in while admitted and not
    /// settled.
    fn unsettled_index(&self, r: u32) -> Option<usize> {
        match self.held_index(r) {
            Some(HELD_FAST) => Some(UNSETTLED_FAST),
            Some(HELD_SLOW) => Some(UNSETTLED_SLOW),
            _ => None,
        }
    }

    /// `r` settled or its connection ended: it stops counting as unsettled.
    fn stop_unsettled(&mut self, r: u32) {
        if let Some(i) = self.unsettled_index(r) {
            self.advance_area();
            self.held[i] -= u64::from(self.replies[r as usize].slots);
        }
    }

    /// Run the order's admission pass and apply its grants.
    fn admission_pass(&mut self) -> bool {
        if self.fifos.iter().all(VecDeque::is_empty) {
            return false;
        }
        self.watch();
        let room = self.a.order == Order::O4s;
        let views: [Vec<policy::Waiter>; 2] = std::array::from_fn(|pool| {
            self.fifos[pool]
                .iter()
                .map(|&r| {
                    let reply = &self.replies[r as usize];
                    let conn = &self.conns[reply.conn as usize];
                    policy::Waiter {
                        conn: reply.conn,
                        slots: reply.slots,
                        joined_at: reply.joined_at,
                        seq: reply.seq,
                        conn_unsettled: !conn.unsettled.is_empty(),
                        conn_waited: conn.last_waited,
                        conn_room: !room
                            || conn.occupancy(self.now) + conn.pending + reply.len <= conn.kbuf,
                    }
                })
                .collect()
        });
        let state = policy::State {
            now: self.now,
            fifos: [&views[0], &views[1]],
            free: self.free,
            pool_slots: self.capacity[MAIN],
            marked: self.marked,
            latched: self.latched,
            o6_ns: self.o6_ns,
            budget: self.budget,
        };
        let grants = policy::pass(self.a.order, &state);
        if grants.is_empty() {
            return false;
        }
        let admitted: Vec<(u32, bool)> = grants
            .iter()
            .map(
                |&Grant {
                     pool,
                     index,
                     passed,
                 }| (self.fifos[pool][index], passed),
            )
            .collect();
        for (r, passed) in admitted {
            if cfg!(debug_assertions) {
                self.check_connection_order(r);
            }
            if passed {
                self.record_pass(r);
            }
            self.fifo_remove(r);
            self.admit(r, passed);
        }
        true
    }

    /// No earlier waiter of the reply's connection is in either FIFO. The
    /// policy guarantees it; this catches a policy that does not. It visits
    /// both FIFOs, so only debug builds, which the tests use, run it.
    fn check_connection_order(&self, r: u32) {
        let reply = &self.replies[r as usize];
        for fifo in &self.fifos {
            for &w in fifo {
                let o = &self.replies[w as usize];
                assert!(
                    w == r || o.conn != reply.conn || o.seq > reply.seq,
                    "{} admitted reply {r} ahead of reply {w} on its connection",
                    self.a.order.name()
                );
            }
        }
    }

    /// A waiter passes each waiting episode head it was behind.
    fn record_pass(&mut self, r: u32) {
        let seq = self.replies[r as usize].seq;
        for &e in &self.waiting_heads {
            let ep = &mut self.episodes[e];
            let h = ep.wait.expect("a waiting head has a waiter");
            if self.replies[h as usize].seq < seq {
                ep.passed.push(r);
            }
        }
    }

    /// Take the reply's slots and queue its bytes on its connection.
    fn admit(&mut self, r: u32, passed: bool) {
        self.advance_area();
        let held = self.held_index(r);
        let unsettled = self.unsettled_index(r);
        let reply = &mut self.replies[r as usize];
        reply.stage = Stage::Admitted;
        reply.admitted_at = self.now;
        reply.held = reply.slots;
        self.free[reply.pool] -= reply.slots;
        if passed && self.a.order.marks() {
            reply.marked = true;
            self.marked += reply.slots;
        }
        let (c, len, slots, kind) = (reply.conn, reply.len, reply.slots, reply.kind);
        let (scheduled, joined) = (self.now - reply.scheduled_at, self.now - reply.joined_at);
        let in_window = reply.in_window;
        let slot_size = self.slot_size[reply.pool];
        for i in [held, unsettled].into_iter().flatten() {
            self.held[i] += u64::from(slots);
        }
        self.holding.insert(r);
        let (first, last) = (self.first_send(r), self.last_send(r));
        if kind != Kind::Outside && in_window && first {
            let s = self.stats(r);
            s.admitted += 1;
            s.passed += u64::from(passed);
            s.scheduled_delay.push(scheduled);
            s.join_delay.push(joined);
        }
        let conn = &mut self.conns[c as usize];
        conn.pending += len;
        for i in 0..u64::from(slots) {
            conn.queue.push_back(Chunk {
                reply: r,
                bytes: slot_size.min(len - i * slot_size),
            });
        }
        if kind != Kind::Outside {
            conn.unsettled.push_back(r);
            if conn.unsettled.len() == 1 {
                self.arm_settle(r);
            }
        }
        if let Some(l) = self.replies[r as usize].parent {
            if first {
                self.replies[l as usize].admitted_at = self.now;
            }
            if last {
                // The send of the last piece returns: the connection reads
                // again.
                self.conns[c as usize].streaming = None;
            }
        }
        if kind == Kind::Large && first {
            let e = self.conns[c as usize].owner;
            if self.episodes[e].head == Some(self.logical(r)) {
                self.episodes[e].outcome = Outcome::Admitted;
                self.episodes[e].admitted_at = Some(self.now);
            }
        }
        self.track_free(false);
        self.to_pump.insert(c);
        self.to_serve.insert(c);
        self.watch();
    }

    /// Start the settle clock of `r`, now its connection's oldest unsettled
    /// reply: from its admission or, if later, the settlement of the reply
    /// before it.
    fn arm_settle(&mut self, r: u32) {
        let reply = &self.replies[r as usize];
        let since = reply
            .admitted_at
            .max(self.conns[reply.conn as usize].last_settled_at);
        let deadline = since + self.a.settle_ms * MS;
        self.replies[r as usize].settle_deadline = deadline;
        self.schedule(deadline, Event::SettleDeadline(r));
    }

    /// Write the connection's queued bytes while its buffer has room.
    fn pump(&mut self, c: u32) {
        loop {
            let run_slots = self.a.run_slots;
            let conn = &mut self.conns[c as usize];
            if !conn.alive || conn.blocked {
                return;
            }
            if conn.run.is_empty() {
                if conn.queue.is_empty() {
                    return;
                }
                let n = conn.queue.len().min(run_slots);
                conn.run = conn.queue.drain(..n).collect();
                conn.run_cursor = 0;
                conn.run_done = 0;
                conn.run_left = conn.run.iter().map(|ch| ch.bytes).sum();
            }
            let left = conn.run_left;
            let n = conn.take(self.now, left);
            if n == 0 {
                self.block(c);
                return;
            }
            self.write(c, n);
            if self.conns[c as usize].run_left > 0 {
                self.block(c);
                return;
            }
            let run = std::mem::take(&mut self.conns[c as usize].run);
            for chunk in run {
                self.release_slot(chunk.reply);
            }
        }
    }

    /// Move `n` bytes of the run into the kernel buffer, settling each reply
    /// whose last byte goes in.
    fn write(&mut self, c: u32, n: u64) {
        let now = self.now;
        let Sim { conns, replies, .. } = self;
        let conn = &mut conns[c as usize];
        if conn.read_at(now) >= conn.written {
            conn.read_base = conn.written;
            conn.read_t = now;
        }
        let mut offset = conn.written;
        conn.written += n;
        conn.run_left -= n;
        conn.pending -= n;
        let mut left = n;
        let mut settled = Vec::new();
        while left > 0 {
            let (r, bytes) = {
                let chunk = &conn.run[conn.run_cursor];
                (chunk.reply, chunk.bytes)
            };
            let take = (bytes - conn.run_done).min(left);
            let reply = &mut replies[r as usize];
            reply.entered += take;
            conn.run_done += take;
            left -= take;
            offset += take;
            if reply.entered == reply.len {
                settled.push((r, offset));
            }
            if conn.run_done == bytes {
                conn.run_cursor += 1;
                conn.run_done = 0;
            }
        }
        for (r, offset) in settled {
            self.settle(r, offset);
        }
    }

    /// The reply's last byte, at `offset` in the connection's stream, is in
    /// the kernel buffer.
    fn settle(&mut self, r: u32, offset: u64) {
        let reply = &mut self.replies[r as usize];
        reply.stage = Stage::Settled;
        reply.settled_at = Some(self.now);
        let (c, kind, waited, in_window) = (reply.conn, reply.kind, reply.waited, reply.in_window);
        let conn = &mut self.conns[c as usize];
        let delivered = (conn.read_bps > 0).then(|| conn.time_reading(offset));
        self.replies[r as usize].delivered_at = delivered;
        if kind == Kind::Outside {
            return;
        }
        let conn = &mut self.conns[c as usize];
        let oldest = conn.unsettled.pop_front();
        assert_eq!(oldest, Some(r), "replies settle in admission order");
        self.stop_unsettled(r);
        let conn = &mut self.conns[c as usize];
        conn.last_settled_at = self.now;
        conn.last_waited = waited;
        let next = conn.unsettled.front().copied();
        let last = self.last_send(r);
        if in_window && last {
            self.stats(r).replies += 1;
        }
        if let Some(next) = next {
            self.arm_settle(next);
        }
        let l = self.logical(r);
        if l != r {
            if last {
                let piece_delivered = self.replies[r as usize].delivered_at;
                let reply = &mut self.replies[l as usize];
                reply.stage = Stage::Settled;
                reply.settled_at = Some(self.now);
                reply.delivered_at = piece_delivered;
            } else {
                self.to_stream.insert(c);
            }
        }
        if last && kind.source() == EPISODE {
            self.conns[c as usize].settled.push(l);
        }
        self.to_serve.insert(c);
    }

    /// One slot of `r` returns.
    fn release_slot(&mut self, r: u32) {
        self.advance_area();
        if let Some(i) = self.held_index(r) {
            self.held[i] -= 1;
        }
        let reply = &mut self.replies[r as usize];
        reply.held -= 1;
        self.free[reply.pool] += 1;
        if reply.marked {
            self.marked -= 1;
        }
        if reply.held == 0 {
            reply.released_at = Some(self.now);
            self.holding.remove(&r);
        }
        self.watch();
    }

    /// The connection's send filled its buffer and waits. Every reply with
    /// bytes left in the run waited for room (O4w).
    fn block(&mut self, c: u32) {
        let Sim { conns, replies, .. } = self;
        let conn = &mut conns[c as usize];
        for chunk in &conn.run[conn.run_cursor..] {
            replies[chunk.reply as usize].waited = true;
        }
        conn.blocked = true;
        conn.token += 1;
        if let Some(at) = conn.writable_at(self.now) {
            let token = conn.token;
            self.schedule(at, Event::Writable(c, token));
        }
        self.blocked.insert(c);
        if self.a.backstop_ms > 0 && self.backstop_at.is_none() {
            let at = self.now + self.a.backstop_ms * MS;
            self.backstop_at = Some(at);
            self.schedule(at, Event::Backstop);
        }
    }

    /// End a connection: return its slots, drop its waiters, unsettled
    /// replies and unread requests, and discard its kernel buffer.
    /// `trigger` is counted by `why`; the connection's other outstanding
    /// replies as failed for a peer close and dropped otherwise. A reply
    /// sent in pieces counts once, whichever of its pieces is outstanding.
    fn end_conn(&mut self, c: u32, trigger: Option<u32>, why: End) {
        if !self.conns[c as usize].alive {
            return;
        }
        if let Some(r) = trigger
            && self.replies[r as usize].in_window
        {
            let s = self.stats(r);
            match why {
                End::AdmitTimeout => s.admit_timeouts += 1,
                End::SettleAbort => s.settle_aborts += 1,
                End::RoomTimeout => s.room_timeouts += 1,
                End::Refused => s.refused += 1,
                End::Failed | End::PeerClosed => s.failed += 1,
            }
        }
        let conn = &mut self.conns[c as usize];
        let sending = conn.waiting > 0
            || !conn.unsettled.is_empty()
            || conn.streaming.is_some()
            || !conn.run.is_empty()
            || !conn.queue.is_empty();
        if self.now >= self.window.0 && (why != End::PeerClosed || sending) {
            let cause = End::ALL.iter().position(|&e| e == why).expect("listed");
            self.ends[cause][conn.kind.index()] += 1;
        }
        conn.alive = false;
        conn.ended_at = Some(self.now);
        conn.blocked = false;
        conn.gate = None;
        let streaming = conn.streaming.take();
        let chunks: Vec<u32> = conn
            .run
            .drain(..)
            .chain(conn.queue.drain(..))
            .map(|ch| ch.reply)
            .collect();
        let unsettled: Vec<u32> = conn.unsettled.drain(..).collect();
        let requests: Vec<u32> = conn.requests.drain(..).collect();
        let settled = std::mem::take(&mut conn.settled);
        let (kind, owner) = (conn.kind, conn.owner);
        self.blocked.remove(&c);
        for &r in &unsettled {
            self.stop_unsettled(r);
        }
        for r in chunks {
            self.release_slot(r);
        }
        let waiters: Vec<u32> = self
            .fifos
            .iter()
            .flatten()
            .copied()
            .filter(|&w| self.replies[w as usize].conn == c)
            .collect();
        for &r in &waiters {
            self.fifo_remove(r);
        }
        let sends: Vec<u32> = waiters.into_iter().chain(unsettled).collect();
        let mut outstanding: BTreeSet<u32> = sends.iter().map(|&r| self.logical(r)).collect();
        outstanding.extend(streaming);
        if let Some(t) = trigger {
            outstanding.remove(&self.logical(t));
        }
        for r in outstanding {
            if self.replies[r as usize].in_window {
                let s = self.stats(r);
                if why == End::PeerClosed {
                    s.failed += 1;
                } else {
                    s.dropped += 1;
                }
            }
            self.replies[r as usize].stage = Stage::Ended;
        }
        for r in sends.into_iter().chain(requests).chain(trigger) {
            self.replies[r as usize].stage = Stage::Ended;
            let l = self.logical(r);
            self.replies[l as usize].stage = Stage::Ended;
        }
        for r in settled {
            let reply = &mut self.replies[r as usize];
            if reply.delivered_at.is_some_and(|d| d > self.now) {
                reply.delivered_at = None;
            }
        }
        match kind {
            Kind::Fast | Kind::Slow => {
                self.lose_pending(owner);
                let new = self.open(kind, owner);
                let client = &mut self.clients[owner];
                client.conn = new;
                client.reconnects += 1;
            }
            Kind::Large => {
                let ep = &mut self.episodes[owner];
                if let Some(h) = ep.head {
                    let head = &mut self.replies[h as usize];
                    if head.delivered_at.is_some_and(|d| d > self.now) {
                        head.delivered_at = None;
                    }
                    if head.stage == Stage::Ended {
                        ep.outcome = match why {
                            End::AdmitTimeout => Outcome::AdmitTimeout,
                            End::SettleAbort => Outcome::SettleAbort,
                            End::RoomTimeout => Outcome::RoomTimeout,
                            _ => Outcome::Failed,
                        };
                    }
                }
            }
            _ => {}
        }
    }

    /// Count what the clients read by the end of the drain, and lose the
    /// rest, as admission-load does when its drain ends.
    fn finish(&mut self) {
        self.now = self.end;
        for i in 0..self.clients.len() {
            self.lose_pending(i);
        }
        self.advance_area();
    }

    fn report(&self) -> Value {
        let class = |c: usize| {
            let mut all = Stats::default();
            for s in &self.stats[c] {
                all.add(s);
            }
            let mut v = all.report();
            v["fast"] = self.stats[c][FAST].report();
            v["slow"] = self.stats[c][SLOW].report();
            v["episode"] = self.stats[c][EPISODE].report();
            v
        };
        let e2e = |kind: Kind| {
            let clients = self.clients.iter().filter(|c| c.kind == kind);
            let mut lat: Vec<u64> = clients
                .clone()
                .flat_map(|c| c.latencies.iter().copied())
                .collect();
            lat.sort_unstable();
            let within_ns = self.a.admit_ms * MS;
            let within = lat.iter().filter(|&&l| l <= within_ns).count() as u64;
            let offered: u64 = clients.clone().map(|c| c.offered).sum();
            json!({
                "offered": offered,
                "delivered_within": within,
                "delivered_late": lat.len() as u64 - within,
                "lost": clients.clone().map(|c| c.lost).sum::<u64>(),
                "not_within": offered - within,
                "reconnects": clients.map(|c| c.reconnects).sum::<u64>(),
                "within_ms": self.a.admit_ms,
                "latency_us": percentiles(&lat),
            })
        };
        let outside = self.clients.iter().filter(|c| c.kind == Kind::Outside);
        let episodes: Vec<Value> = self.episodes.iter().map(|e| self.episode(e)).collect();
        let heads: Vec<&Reply> = self
            .episodes
            .iter()
            .filter_map(|e| e.head.map(|h| &self.replies[h as usize]))
            .collect();
        let head_admission: Vec<u64> = self
            .episodes
            .iter()
            .filter_map(|e| e.admitted_at.map(|t| t - e.requested_at))
            .collect();
        let head_delivery: Vec<u64> = self
            .episodes
            .iter()
            .filter_map(|e| self.delivery(e))
            .collect();
        let outcome_count = |o: Outcome| self.episodes.iter().filter(|e| e.outcome == o).count();
        let mut waits: [Vec<f64>; HELD_COUNTERS] = Default::default();
        for l in self.episodes.iter().filter_map(|e| e.held_during_wait) {
            for (i, v) in l.into_iter().enumerate() {
                waits[i].push(v);
            }
        }
        json!({
            "params": self.a.params(),
            "model": {
                "pool_slots": self.capacity,
                "slot_size": self.slot_size,
                "budget": self.budget,
                "o6_ms": self.o6_ns / MS,
                "events": self.events_run,
            },
            "small": class(SMALL),
            "large": class(LARGE),
            "small_e2e": e2e(Kind::Fast),
            "slow_e2e": e2e(Kind::Slow),
            "outside": {
                "offered": outside.clone().map(|c| c.offered).sum::<u64>(),
                "sent": outside.clone().map(|c| c.sent).sum::<u64>(),
                "refused": outside.map(|c| c.refused).sum::<u64>(),
            },
            "heads": {
                "episodes": self.episodes.len(),
                "requested": heads.len(),
                "admitted": head_admission.len(),
                "admit_timeouts": outcome_count(Outcome::AdmitTimeout),
                "settle_aborts": outcome_count(Outcome::SettleAbort),
                "failed": outcome_count(Outcome::Failed),
                "still_waiting": outcome_count(Outcome::Waiting),
                "admission_us": percentiles(&head_admission),
                "delivered": head_delivery.len(),
                "delivery_us": percentiles(&head_delivery),
                "l_fast_median": median(&mut waits[HELD_FAST]),
                "l_slow_median": median(&mut waits[HELD_SLOW]),
                "l_unsettled_fast_median": median(&mut waits[UNSETTLED_FAST]),
                "l_unsettled_slow_median": median(&mut waits[UNSETTLED_SLOW]),
            },
            "large_ms": self
                .episodes
                .iter()
                .map(|e| self.delivery(e).map(|d| d / MS))
                .collect::<Vec<_>>(),
            "d": self.report_d(),
            "episodes": episodes,
        })
    }

    /// Experiment D's statistics (see the module docs).
    fn report_d(&self) -> Value {
        let completed: Vec<u64> = self
            .episodes
            .iter()
            .filter_map(|e| self.delivery(e))
            .collect();
        let requested = self.episodes.iter().filter(|e| e.head.is_some()).count();
        let mut sends = [0u64; 6];
        let mut waited = [0u64; 6];
        let mut read: [Vec<u64>; 6] = Default::default();
        let mut asked = [0u64; 6];
        for (i, r) in self.replies.iter().enumerate() {
            if !r.in_window || r.small || r.kind == Kind::Outside {
                continue;
            }
            let k = r.kind.index();
            if r.parent.is_none() {
                asked[k] += 1;
                if let Some(d) = r.delivered_at.filter(|&d| d <= self.end) {
                    read[k].push(d - r.scheduled_at);
                }
            }
            if !self.pieced(i as u32) && r.admitted_at > 0 {
                sends[k] += 1;
                waited[k] += u64::from(r.waited);
            }
        }
        let by_kind = |v: &[u64; 6]| -> Value {
            Value::Object(
                Kind::ALL
                    .iter()
                    .zip(v)
                    .filter(|&(_, &n)| n > 0)
                    .map(|(k, &n)| (k.name().to_string(), json!(n)))
                    .collect(),
            )
        };
        let replies = |kind: Kind| {
            let k = kind.index();
            json!({
                "requested": asked[k],
                "completed": read[k].len(),
                "completion_us": percentiles(&read[k]),
            })
        };
        let ends: serde_json::Map<String, Value> = End::ALL
            .iter()
            .zip(&self.ends)
            .map(|(e, n)| (e.name().to_string(), by_kind(n)))
            .collect();
        let min = |f: fn(&Episode) -> Option<u32>| self.episodes.iter().filter_map(f).min();
        json!({
            "large": {
                "requested": requested,
                "completed": completed.len(),
                "not_completed": requested - completed.len(),
                "completion_us": percentiles(&completed),
                "min_free": min(|e| e.min_free),
                "min_free_sampled": min(|e| e.min_free_sampled),
            },
            "drain": replies(Kind::Drain),
            "stall": replies(Kind::Stall),
            "sends": by_kind(&sends),
            "sends_waited_for_room": by_kind(&waited),
            "gate_waits": by_kind(&self.gate_waits),
            "ends": Value::Object(ends),
        })
    }

    /// The head's time from request to its last byte read, if it was read
    /// by the end of the drain.
    fn delivery(&self, e: &Episode) -> Option<u64> {
        let h = e.head?;
        let at = self.replies[h as usize].delivered_at?;
        (at <= self.end).then(|| at - e.requested_at)
    }

    fn episode(&self, e: &Episode) -> Value {
        let admitted = e.admitted_at;
        let passed: Vec<Value> = e
            .passed
            .iter()
            .map(|&r| {
                let p = &self.replies[r as usize];
                json!({
                    "kind": format!("{:?}", p.kind).to_lowercase(),
                    "slots": p.slots,
                    "held_us": p.released_at.map(|t| us(t - p.admitted_at)),
                })
            })
            .collect();
        let marks = self.a.order.marks();
        json!({
            "start_ms": e.start / MS,
            "outcome": e.outcome.name(),
            "head_admission_us": admitted.map(|t| us(t - e.requested_at)),
            "head_delivery_us": self.delivery(e).map(us),
            "l_unsettled": e.held_during_wait.map(|l| json!({
                "small_fast": l[UNSETTLED_FAST],
                "small_slow": l[UNSETTLED_SLOW],
            })),
            "l": e.held_during_wait.map(|l| json!({
                "small_fast": l[HELD_FAST],
                "small_slow": l[HELD_SLOW],
                "outside": l[HELD_OUTSIDE],
            })),
            "max_b": marks.then_some(e.max_marked),
            "covered_to_admission_us": e
                .covered_at
                .zip(admitted)
                .map(|(c, a)| us(a - c)),
            "min_free": e.min_free,
            "min_free_sampled": e.min_free_sampled,
            "pieces": e.head.map(|h| self.replies[h as usize].pieces),
            "passed": passed,
        })
    }

    /// The invariants every event must leave: F plus the held slots is each
    /// pool's size, B is the slots marked replies hold, and each
    /// connection's waiter count matches the FIFOs.
    #[cfg(test)]
    fn audit(&self) {
        let mut held = [0u32; 2];
        let mut marked = 0;
        for &r in &self.holding {
            let reply = &self.replies[r as usize];
            assert!(reply.held > 0);
            held[reply.pool] += reply.held;
            if reply.marked {
                marked += reply.held;
            }
        }
        for pool in 0..2 {
            assert_eq!(held[pool] + self.free[pool], self.capacity[pool]);
        }
        assert_eq!(marked, self.marked, "B is the slots marked replies hold");
        let mut unsettled = [0u64; HELD_COUNTERS];
        for conn in &self.conns {
            for &r in &conn.unsettled {
                if let Some(i) = self.unsettled_index(r) {
                    unsettled[i] += u64::from(self.replies[r as usize].slots);
                }
            }
        }
        for i in [UNSETTLED_FAST, UNSETTLED_SLOW] {
            assert_eq!(
                unsettled[i], self.held[i],
                "L unsettled counts the unsettled replies"
            );
        }
        for (c, conn) in self.conns.iter().enumerate() {
            let waiting = self
                .fifos
                .iter()
                .flatten()
                .filter(|&&w| self.replies[w as usize].conn == c as u32)
                .count();
            assert_eq!(waiting as u32, conn.waiting);
        }
        // A reply has at most one piece waiting or unsettled, none while a
        // piece waits at the gate, and none past its last.
        for conn in self.conns.iter().filter(|c| c.alive) {
            let Some(l) = conn.streaming else {
                assert!(
                    conn.gate.is_none(),
                    "a gate waits only for a streaming reply"
                );
                continue;
            };
            let open = self
                .fifos
                .iter()
                .flatten()
                .chain(&conn.unsettled)
                .filter(|&&r| self.replies[r as usize].parent == Some(l))
                .count();
            assert!(open <= 1, "{open} pieces of reply {l} are open at once");
            assert!(conn.gate.is_none() || open == 0);
            assert!(self.replies[l as usize].pieces <= self.piece_count(l));
        }
    }
}

fn us(ns: u64) -> f64 {
    ns as f64 / 1000.0
}

/// admission-load's percentile: the value at rank ceil(n * p).
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let i = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[i]
}

/// p50, p99, p999 and max, in microseconds, or null for none.
fn percentiles(values: &[u64]) -> Value {
    if values.is_empty() {
        return Value::Null;
    }
    let mut v = values.to_vec();
    v.sort_unstable();
    json!({
        "n": v.len(),
        "p50": us(percentile(&v, 0.50)),
        "p99": us(percentile(&v, 0.99)),
        "p999": us(percentile(&v, 0.999)),
        "max": us(*v.last().unwrap()),
    })
}

fn median(v: &mut [f64]) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(f64::total_cmp);
    let n = v.len();
    Some(if n % 2 == 1 {
        v[n / 2]
    } else {
        (v[n / 2 - 1] + v[n / 2]) / 2.0
    })
}

fn main() {
    let args = Args::parse();
    if let Err(e) = args.check() {
        eprintln!("admission-model: {e}");
        std::process::exit(2);
    }
    let mut sim = Sim::new(&args);
    sim.run();
    println!("{}", sim.report());
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, ValueEnum};

    use super::policy::{State, Waiter};
    use super::*;

    fn waiter(conn: u32, slots: u32, seq: u64) -> Waiter {
        Waiter {
            conn,
            slots,
            joined_at: 0,
            seq,
            conn_unsettled: false,
            conn_waited: false,
            conn_room: true,
        }
    }

    fn state<'a>(main: &'a [Waiter], small: &'a [Waiter], free: [u32; 2]) -> State<'a> {
        State {
            now: 0,
            fifos: [main, small],
            free,
            pool_slots: 512,
            marked: 0,
            latched: false,
            o6_ns: u64::MAX,
            budget: u32::MAX,
        }
    }

    /// A head of 10 slots, and waiters of 6, 3 and 2 behind it, each on its
    /// own connection.
    fn blocked_head() -> Vec<Waiter> {
        vec![
            waiter(1, 10, 1),
            waiter(2, 6, 2),
            waiter(3, 3, 3),
            waiter(4, 2, 4),
        ]
    }

    fn grants(pool: usize, indices: &[usize], passed: bool) -> Vec<Grant> {
        indices
            .iter()
            .map(|&index| Grant {
                pool,
                index,
                passed,
            })
            .collect()
    }

    fn args(extra: &[&str]) -> Args {
        Args::try_parse_from(std::iter::once("admission-model").chain(extra.iter().copied()))
            .expect("valid arguments")
    }

    fn run(a: &Args) -> Value {
        a.check().expect("runnable parameters");
        let mut sim = Sim::new(a);
        sim.run();
        sim.report()
    }

    /// As `run`, checking `Sim::audit` after every event.
    fn run_audited(a: &Args) -> Value {
        a.check().expect("runnable parameters");
        let mut sim = Sim::new(a);
        while sim.step() {
            sim.audit();
        }
        sim.finish();
        sim.report()
    }

    fn without_order(mut v: Value) -> Value {
        v["params"]["order"] = Value::Null;
        v
    }

    /// Slow readers whose buffers fill, so replies to them hold slots while
    /// the head waits, and some are admitted past it.
    const SLOW: [&str; 14] = [
        "--slow-conns",
        "16",
        "--slow-rate",
        "50",
        "--slow-size",
        "4096",
        "--slow-read-bps",
        "65536",
        "--slow-kbuf",
        "65536",
        "--warmup",
        "1",
        "--duration",
        "8",
    ];

    fn slow(order: &str, more: &[&str]) -> Args {
        let mut v = vec!["--order", order];
        v.extend_from_slice(&SLOW);
        v.extend_from_slice(more);
        args(&v)
    }

    #[test]
    fn o0_admits_only_the_head() {
        let fifo = blocked_head();
        assert!(policy::pass(Order::O0, &state(&fifo, &[], [8, 0])).is_empty());
        assert_eq!(
            policy::pass(Order::O0, &state(&fifo, &[], [12, 0])),
            grants(MAIN, &[0], false)
        );
        assert_eq!(
            policy::pass(Order::O0, &state(&fifo, &[], [16, 0])),
            grants(MAIN, &[0, 1], false)
        );
    }

    #[test]
    fn o0_admits_nothing_past_the_head_in_a_run_where_o2_does() {
        let v = run_audited(&slow("o0", &[]));
        assert_eq!(v["small"]["passed"], 0);
        assert_eq!(v["large"]["passed"], 0);
        let v = run(&slow("o2", &[]));
        assert!(v["small"]["passed"].as_u64().unwrap() > 0);
    }

    #[test]
    fn o2_admits_first_fit_behind_a_blocked_head() {
        let fifo = blocked_head();
        assert_eq!(
            policy::pass(Order::O2, &state(&fifo, &[], [8, 0])),
            grants(MAIN, &[1, 3], true)
        );
    }

    #[test]
    fn no_order_admits_a_reply_ahead_of_an_earlier_waiter_on_its_connection() {
        // Connection 2's first waiter does not fit; its second would.
        let fifo = vec![waiter(1, 10, 1), waiter(2, 6, 2), waiter(2, 1, 3)];
        for &order in Order::value_variants() {
            let g = policy::pass(order, &state(&fifo, &[], [5, 0]));
            assert!(g.is_empty(), "{order:?} admitted {g:?}");
        }
        // O5: connection 2's earlier waiter is in the other pool. Its small
        // reply is held off, and the waiter behind it becomes the head.
        let main = vec![waiter(1, 10, 1), waiter(2, 6, 2)];
        let small = vec![waiter(2, 1, 3), waiter(5, 1, 4)];
        assert_eq!(
            policy::pass(Order::O5, &state(&main, &small, [5, 8])),
            grants(SMALL_POOL, &[1], false)
        );
    }

    #[test]
    fn o3_passes_only_while_free_and_marked_are_short_of_the_head() {
        let fifo = blocked_head();
        let mut s = state(&fifo, &[], [8, 0]);
        s.marked = 1;
        assert_eq!(policy::pass(Order::O3, &s), grants(MAIN, &[1, 3], true));
        s.marked = 2;
        assert!(policy::pass(Order::O3, &s).is_empty());
        s.marked = 0;
        s.latched = true;
        assert!(policy::pass(Order::O3, &s).is_empty());
    }

    #[test]
    fn o3_judges_a_new_head_by_its_own_need() {
        // The 10-slot head goes, leaving F = 2 for a 20-slot head.
        let fifo = vec![waiter(1, 10, 1), waiter(2, 20, 2), waiter(3, 1, 3)];
        let mut s = state(&fifo, &[], [12, 0]);
        s.marked = 17;
        let mut want = grants(MAIN, &[0], false);
        want.extend(grants(MAIN, &[2], true));
        assert_eq!(policy::pass(Order::O3, &s), want);
        s.marked = 18;
        assert_eq!(policy::pass(Order::O3, &s), grants(MAIN, &[0], false));
    }

    #[test]
    fn o3_latch_holds_for_the_rest_of_the_heads_wait() {
        let a = args(&[
            "--order",
            "o3",
            "--small-conns",
            "0",
            "--warmup",
            "4",
            "--duration",
            "4",
        ]);
        let mut sim = Sim::new(&a);
        while sim.events.peek().is_some_and(|e| e.at <= 4_200 * MS) {
            sim.step();
        }
        // F = 128 against the head's 448: not latched.
        assert!(!sim.latched);
        sim.free[MAIN] = 448;
        sim.watch();
        assert!(sim.latched);
        // F + B falls back below H, as when a send outside the FIFO takes
        // slots: the latch stays.
        sim.free[MAIN] = 100;
        sim.watch();
        assert!(sim.latched);
        // A new head starts unlatched.
        let head = sim.fifos[MAIN].pop_front().unwrap();
        sim.note_head();
        assert!(!sim.latched);
        sim.fifos[MAIN].push_front(head);
        sim.note_head();
        assert!(!sim.latched);
    }

    #[test]
    fn o4_passes_only_onto_connections_with_nothing_unsettled() {
        let mut fifo = blocked_head();
        fifo[1].conn_unsettled = true;
        let s = state(&fifo, &[], [8, 0]);
        assert_eq!(policy::pass(Order::O3, &s), grants(MAIN, &[1, 3], true));
        assert_eq!(policy::pass(Order::O4, &s), grants(MAIN, &[2, 3], true));
    }

    #[test]
    fn o4w_and_o7w_pass_only_onto_connections_whose_last_send_did_not_wait() {
        let mut fifo = blocked_head();
        fifo[1].conn_waited = true;
        let s = state(&fifo, &[], [8, 0]);
        assert_eq!(policy::pass(Order::O4, &s), grants(MAIN, &[1, 3], true));
        assert_eq!(policy::pass(Order::O4w, &s), grants(MAIN, &[2, 3], true));
        assert_eq!(policy::pass(Order::O7w, &s), grants(MAIN, &[2, 3], true));
    }

    #[test]
    fn o4s_passes_only_where_the_kernel_buffer_has_room() {
        let mut fifo = blocked_head();
        fifo[1].conn_room = false;
        let s = state(&fifo, &[], [8, 0]);
        assert_eq!(policy::pass(Order::O4s, &s), grants(MAIN, &[2, 3], true));
    }

    #[test]
    fn o6_passes_only_during_the_first_d_of_the_heads_wait() {
        let fifo = blocked_head();
        let mut s = state(&fifo, &[], [8, 0]);
        s.o6_ns = 100;
        s.now = 99;
        assert_eq!(policy::pass(Order::O6, &s), grants(MAIN, &[1, 3], true));
        s.now = 100;
        assert!(policy::pass(Order::O6, &s).is_empty());
    }

    #[test]
    fn o7_passes_only_within_the_smaller_of_r_and_p_less_h() {
        let fifo = blocked_head();
        let mut s = state(&fifo, &[], [8, 0]);
        s.budget = 6;
        assert_eq!(policy::pass(Order::O7, &s), grants(MAIN, &[1], true));
        s.budget = 8;
        assert_eq!(policy::pass(Order::O7, &s), grants(MAIN, &[1, 3], true));
        // P - H = 5 binds.
        s.pool_slots = 15;
        assert_eq!(policy::pass(Order::O7, &s), grants(MAIN, &[2, 3], true));
        // B counts sends admitted past earlier heads.
        s.marked = 4;
        assert!(policy::pass(Order::O7, &s).is_empty());
    }

    #[test]
    fn o5_admits_a_small_pool_head_while_the_large_head_waits() {
        let main = vec![waiter(1, 7, 1)];
        let small = vec![waiter(2, 1, 2), waiter(3, 1, 3)];
        assert_eq!(
            policy::pass(Order::O5, &state(&main, &small, [3, 1])),
            grants(SMALL_POOL, &[0], false)
        );
    }

    #[test]
    fn o5_splits_the_pool_bytes_by_the_small_share() {
        assert_eq!(
            args(&["--order", "o5"]).pools(),
            Ok(([7, 64], [1 << 20, 16384]))
        );
        assert!(
            args(&["--order", "o5", "--large-size", "8388608"])
                .check()
                .is_err()
        );
        assert!(
            args(&["--order", "o5", "--small-pool-slots", "8"])
                .check()
                .is_err()
        );
    }

    #[test]
    fn o1_small_replies_take_slots_without_the_fifo() {
        let v = run(&args(&[
            "--order",
            "o1",
            "--warmup",
            "1",
            "--duration",
            "8",
        ]));
        assert_eq!(v["small"]["join_to_admission_us"]["max"], 0.0);
        assert_eq!(v["small"]["scheduled_to_admission_us"]["max"], 0.0);
        assert_eq!(v["heads"]["admitted"], 2);
    }

    #[test]
    fn b_always_equals_the_slots_marked_replies_hold() {
        for order in ["o3", "o4", "o4s", "o4w", "o7", "o7w"] {
            let v = run_audited(&slow(order, &["--pipeline", "4"]));
            let max_b = v["episodes"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|e| e["max_b"].as_u64())
                .max();
            assert!(max_b > Some(0), "{order}: no send was admitted past a head");
        }
    }

    #[test]
    fn o4_equals_o3_with_one_reply_per_connection_and_differs_with_four() {
        assert_eq!(
            without_order(run(&slow("o3", &[]))),
            without_order(run(&slow("o4", &[])))
        );
        assert_ne!(
            without_order(run(&slow("o3", &["--pipeline", "4"]))),
            without_order(run(&slow("o4", &["--pipeline", "4"])))
        );
    }

    #[test]
    fn a_run_is_identical_for_the_same_arguments_and_seed() {
        let a = slow("o3", &["--seed", "7", "--outside-rate", "500"]);
        assert_eq!(run(&a).to_string(), run(&a).to_string());
        let b = slow("o3", &["--seed", "8", "--outside-rate", "500"]);
        assert_ne!(
            without_order(run(&a))["small"],
            without_order(run(&b))["small"]
        );
    }

    #[test]
    fn under_o0_the_head_is_admitted_when_the_stalled_peers_are_aborted() {
        let a = args(&["--small-conns", "0", "--warmup", "4", "--duration", "4"]);
        let mut sim = Sim::new(&a);
        while sim.events.peek().is_some_and(|e| e.at <= 4_200 * MS) {
            sim.step();
        }
        // Each stalled peer asked for 192 slots at 4 s. Two runs of 32 slots
        // (1 MiB) went into its 1 MiB + 4 KiB buffer and returned; the third
        // run is 4 KiB in and holds its slots, so each peer holds 128. The
        // head, at 4.2 s, needs 448 of the 128 free.
        assert_eq!(sim.free[MAIN], 128);
        let head = sim.fifos[MAIN][0];
        assert_eq!(sim.fifos[MAIN].len(), 1);
        assert_eq!(sim.replies[head as usize].slots, 448);
        sim.run();
        let v = sim.report();
        // The peers are aborted at 5 s, 1000 ms after their admission, and
        // the head is admitted at once: 800 ms after it asked.
        assert_eq!(v["large"]["settle_aborts"], 3);
        assert_eq!(v["heads"]["admission_us"]["max"], 800_000.0);
        assert_eq!(v["heads"]["admission_us"]["n"], 1);
        // Its 7 MiB are read at 1 GiB/s from 5 s without the buffer
        // emptying: ceil(7 * 2^20 * 10^9 / 2^30) ns after admission.
        assert_eq!(
            v["episodes"][0]["head_delivery_us"],
            us(800 * MS + 6_835_938)
        );
    }

    #[test]
    fn a_runs_slots_return_together() {
        // A buffer 1 B short of 1 MiB takes one run of 32 slots and part of
        // the next, or 63 single slots and part of the 64th.
        let at_head = |run_slots: &str| {
            let a = args(&[
                "--small-conns",
                "0",
                "--warmup",
                "4",
                "--duration",
                "4",
                "--stall-kbuf",
                "1048575",
                "--run-slots",
                run_slots,
            ]);
            let mut sim = Sim::new(&a);
            while sim.events.peek().is_some_and(|e| e.at <= 4_200 * MS) {
                sim.step();
            }
            sim.free[MAIN]
        };
        assert_eq!(at_head("32"), 512 - 3 * 160);
        assert_eq!(at_head("1"), 512 - 3 * 129);
    }

    #[test]
    fn a_draining_peer_reads_its_reply_at_its_rate_and_waits_for_room() {
        for backstop in ["1000", "0"] {
            let a = args(&[
                "--small-conns",
                "0",
                "--stall-peers",
                "0",
                "--drainers",
                "1",
                "--drain-read-bps",
                "1048576",
                "--settle-ms",
                "5000",
                "--large-size",
                "16384",
                "--warmup",
                "1",
                "--duration",
                "8",
                "--backstop-ms",
                backstop,
            ]);
            let mut sim = Sim::new(&a);
            sim.run();
            let drain = sim
                .replies
                .iter()
                .find(|r| r.kind == Kind::Drain)
                .expect("a drainer asked");
            // 3 MiB at 1 MiB/s, from 1 s, with the buffer never empty.
            assert_eq!(drain.delivered_at, Some(4 * SEC));
            assert!(drain.waited);
            assert_eq!(drain.stage, Stage::Settled);
        }
    }

    #[test]
    fn a_waiting_send_resumes_at_the_writable_mark_or_the_backstop_whichever_is_first() {
        // 1.5 MiB to a peer reading 128 KiB/s through a 1 MiB buffer. 1 MiB
        // goes in at 1 s.
        let settled = |backstop: &str| {
            let a = args(&[
                "--small-conns",
                "0",
                "--stall-peers",
                "0",
                "--drainers",
                "1",
                "--drain-size",
                "1572864",
                "--drain-read-bps",
                "131072",
                "--settle-ms",
                "20000",
                "--large-size",
                "16384",
                "--warmup",
                "1",
                "--duration",
                "16",
                "--episode-ms",
                "16000",
                "--backstop-ms",
                backstop,
            ]);
            let mut sim = Sim::new(&a);
            sim.run();
            let drain = sim.replies.iter().find(|r| r.kind == Kind::Drain).unwrap();
            assert_eq!(drain.delivered_at, Some(13 * SEC));
            drain.settled_at.unwrap()
        };
        // Each backstop tick writes the 128 KiB read since the last, and
        // the fourth takes the last 128 KiB, at 5 s. The writable mark
        // (k <= 699,050 B) is first reached 2.67 s after 1 s.
        assert_eq!(settled("1000"), 5 * SEC);
        // Without the backstop: 349,526 B go in at the first mark and the
        // last 174,762 B at the second, when 699,052 B have been read.
        assert_eq!(settled("0"), SEC + (699_052 * SEC).div_ceil(131_072));
    }

    #[test]
    fn a_pipelined_reply_is_timed_from_the_settlement_before_it() {
        let a = slow("o0", &["--pipeline", "4"]);
        let mut sim = Sim::new(&a);
        sim.run();
        let mut later = 0;
        for c in 0..sim.conns.len() as u32 {
            let mut prev: Option<u64> = None;
            for r in sim
                .replies
                .iter()
                .filter(|r| r.conn == c && r.kind == Kind::Slow)
            {
                let Some(settled) = r.settled_at else {
                    continue;
                };
                let since = r.admitted_at.max(prev.unwrap_or(0));
                assert_eq!(r.settle_deadline, since + a.settle_ms * MS);
                later += usize::from(prev.is_some_and(|p| p > r.admitted_at));
                prev = Some(settled);
            }
        }
        assert!(
            later > 0,
            "no reply was admitted before the one ahead of it settled"
        );
    }

    #[test]
    fn l_unsettled_counts_a_backlogged_slow_readers_pipeline() {
        // One slow reader asks for 400 KB/s and reads 64 KiB/s, so under O1
        // it always has --pipeline 4 replies of one slot admitted and
        // unsettled. A settled reply's slot can stay held in a run that has
        // not finished, so L is at least that.
        let v = run_audited(&args(&[
            "--order",
            "o1",
            "--slow-conns",
            "1",
            "--slow-read-bps",
            "65536",
            "--slow-kbuf",
            "65536",
            "--pipeline",
            "4",
            "--warmup",
            "1",
            "--duration",
            "8",
        ]));
        for e in v["episodes"].as_array().unwrap() {
            assert_eq!(e["l_unsettled"]["small_slow"], 4.0);
            assert!(e["l"]["small_slow"].as_f64().unwrap() >= 4.0);
            assert_eq!(e["l_unsettled"]["small_fast"], 0.0);
        }
        // A reader too slow to take a reply within --settle-ms: its
        // connection is aborted with replies unsettled, which stop counting.
        let v = run_audited(&args(&[
            "--slow-conns",
            "2",
            "--slow-read-bps",
            "2048",
            "--slow-kbuf",
            "8192",
            "--pipeline",
            "4",
            "--warmup",
            "1",
            "--duration",
            "8",
        ]));
        assert!(v["small"]["slow"]["settle_aborts"].as_u64().unwrap() > 0);
    }

    /// One episode at 1 s with no fast readers, and `more`.
    fn quiet(more: &[&str]) -> Args {
        let mut v = vec!["--small-conns", "0", "--warmup", "1", "--duration", "4"];
        v.extend_from_slice(more);
        args(&v)
    }

    /// The pieces of reply `l`, in order.
    fn pieces_of(sim: &Sim, l: u32) -> Vec<&Reply> {
        let mut p: Vec<&Reply> = sim.replies.iter().filter(|r| r.parent == Some(l)).collect();
        p.sort_by_key(|r| r.piece);
        p
    }

    #[test]
    fn a_reply_of_n_bytes_is_sent_in_ceil_n_over_p_pieces() {
        let a = quiet(&[
            "--stall-peers",
            "0",
            "--large-size",
            "7340033",
            "--stream-piece",
            "131072",
        ]);
        let mut sim = Sim::new(&a);
        sim.run();
        let head = sim.episodes[0].head.unwrap();
        let p = pieces_of(&sim, head);
        // 56 pieces of 128 KiB and one of 1 B, which together are the reply.
        assert_eq!(p.len(), 57);
        assert_eq!(sim.replies[head as usize].pieces, 57);
        assert!(p[..56].iter().all(|r| r.len == 131072 && r.slots == 8));
        assert_eq!((p[56].len, p[56].slots), (1, 1));
        assert!(p.iter().all(|r| r.stage == Stage::Settled));
        assert!(sim.delivery(&sim.episodes[0]).is_some());
        // A reply of at most p bytes is sent whole.
        let v = run(&quiet(&[
            "--stall-peers",
            "0",
            "--large-size",
            "131072",
            "--stream-piece",
            "131072",
        ]));
        assert_eq!(v["episodes"][0]["pieces"], 0);
        assert_eq!(v["d"]["sends"]["large"], 1);
    }

    #[test]
    fn a_reply_has_one_piece_waiting_or_unsettled_at_a_time() {
        // Ungated pieces to stalled peers end partly sent; gated ones wait at
        // the gate; the drainers' pieces wait for room. `Sim::audit` checks
        // after every event that no reply has two pieces open.
        for gate in [&[][..], &["--stream-gate"][..]] {
            let mut more = vec![
                "--stall-peers",
                "8",
                "--stall-gap-us",
                "40",
                "--drainers",
                "2",
                "--drain-read-bps",
                "1048576",
                "--drain-kbuf",
                "262144",
                "--stream-piece",
                "131072",
                "--pipeline",
                "16",
            ];
            more.extend_from_slice(gate);
            let v = run_audited(&quiet(&more));
            assert!(v["d"]["sends"]["stall"].as_u64().unwrap() > 8);
            assert!(v["d"]["sends_waited_for_room"]["drain"].as_u64().unwrap() > 0);
        }
    }

    /// A connection of `kind` opened at time 0 with `more` arguments.
    fn socket(kind: Kind, more: &[&str]) -> Conn {
        let mut sim = Sim::new(&args(more));
        let c = sim.open(kind, 0);
        sim.conns.swap_remove(c as usize)
    }

    #[test]
    fn the_send_queue_takes_a_new_segment_only_below_sndbuf_and_overshoots_by_less_than_one() {
        let ov = ["--stall-seg", "32768", "--skb-overhead", "896"];
        let mut more = vec!["--stall-kbuf", "100000"];
        more.extend_from_slice(&ov);
        let mut conn = socket(Kind::Stall, &more);
        assert_eq!(conn.sndbuf, 100_000);
        // Segments start at q = 0, 33,664 and 67,328, all below 100,000; the
        // fourth would start at 100,992.
        let n = conn.take(0, 1 << 20);
        assert_eq!(n, 3 * 32768);
        conn.written += n;
        assert_eq!(conn.queued(0), 3 * (32768 + 896));
        assert!(conn.queued(0) - conn.sndbuf < 32768 + 896);
        assert_eq!(conn.take(0, 1 << 20), 0);
        // The last segment is topped up without the check: 52,000 B leave a
        // second segment of 19,232 B and q = 53,792 >= 50,000, and the next
        // write still adds 13,536 B to it, and no segment after it.
        let mut more = vec!["--stall-kbuf", "50000"];
        more.extend_from_slice(&ov);
        let mut conn = socket(Kind::Stall, &more);
        let n = conn.take(0, 52_000);
        assert_eq!(n, 52_000);
        conn.written += n;
        assert_eq!(conn.queued(0), 52_000 + 2 * 896);
        let n = conn.take(0, 1 << 20);
        assert_eq!(n, 65536 - 52_000);
        conn.written += n;
        assert_eq!(conn.take(0, 1 << 20), 0);
        // Without segments a write is cut at the limit, as Experiment C's
        // model cut it: K less what is in the buffer.
        let mut conn = socket(Kind::Stall, &["--stall-kbuf", "100000"]);
        assert_eq!(conn.take(0, 1 << 20), 100_000);
    }

    #[test]
    fn bytes_leave_the_send_queue_into_the_peers_receive_window() {
        // K = 64 KiB, of which W = 4 KiB is the peer's: a write takes 64 KiB,
        // 4 KiB of it at once out of the send queue.
        let mut conn = socket(
            Kind::Stall,
            &["--stall-kbuf", "65536", "--stall-rwnd", "4096"],
        );
        assert_eq!(conn.sndbuf, 61440);
        let n = conn.take(0, 1 << 20);
        assert_eq!(n, 65536);
        conn.written += n;
        assert_eq!(conn.queued(0), 61440);
        // With segments, the overhead of a segment stays until all of it is
        // out of the queue: the first 32 KiB segment is 4 KiB out.
        let mut conn = socket(
            Kind::Stall,
            &[
                "--stall-kbuf",
                "1052672",
                "--stall-rwnd",
                "4096",
                "--stall-seg",
                "32768",
                "--skb-overhead",
                "896",
            ],
        );
        let n = conn.take(0, 131072);
        conn.written += n;
        assert_eq!(conn.queued(0), 131072 - 4096 + 4 * 896);
    }

    #[test]
    fn a_gated_piece_waits_until_the_queue_is_at_most_two_thirds_of_sndbuf() {
        // A 384 KiB reply in two pieces of 192 KiB to a drainer reading
        // 1 MiB/s through a 256 KiB buffer. The first piece goes in whole at
        // 1 s and leaves q = 196,608 above the mark, 174,762; the second
        // piece joins when the reader has read 21,846 B.
        let a = quiet(&[
            "--stall-peers",
            "0",
            "--drainers",
            "1",
            "--drain-size",
            "393216",
            "--drain-read-bps",
            "1048576",
            "--drain-kbuf",
            "262144",
            "--stream-piece",
            "196608",
            "--stream-gate",
            "--large-size",
            "16384",
        ]);
        let mut sim = Sim::new(&a);
        sim.run();
        let drain = (0..sim.replies.len() as u32)
            .find(|&r| sim.replies[r as usize].kind == Kind::Drain && sim.pieced(r))
            .unwrap();
        let p = pieces_of(&sim, drain);
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].joined_at, SEC);
        let wait = (21_846 * SEC).div_ceil(1_048_576);
        assert_eq!(p[1].joined_at, SEC + wait);
        assert_eq!(sim.gate_waits[Kind::Drain.index()], 1);
        // With 2 KiB segments of 896 B overhead, a 64 KiB piece is 32
        // segments, q = 94,208 against a mark of 87,381 in a 128 KiB buffer.
        // The mark is reached inside the third segment, at 5,035 B read: q =
        // 65,536 - 5,035 + 30 x 896.
        let a = quiet(&[
            "--stall-peers",
            "0",
            "--drainers",
            "1",
            "--drain-size",
            "131072",
            "--drain-read-bps",
            "1048576",
            "--drain-kbuf",
            "131072",
            "--drain-seg",
            "2048",
            "--skb-overhead",
            "896",
            "--stream-piece",
            "65536",
            "--stream-gate",
            "--large-size",
            "16384",
        ]);
        let mut sim = Sim::new(&a);
        sim.run();
        let drain = (0..sim.replies.len() as u32)
            .find(|&r| sim.replies[r as usize].kind == Kind::Drain && sim.pieced(r))
            .unwrap();
        let p = pieces_of(&sim, drain);
        assert_eq!(p[1].joined_at, SEC + (5_035 * SEC).div_ceil(1_048_576));
    }

    #[test]
    fn a_gated_piece_that_waits_settle_ms_for_room_aborts_its_connection() {
        // One stalled peer, K = 1 MiB + 4 KiB of which 4 KiB is its window.
        // Six 128 KiB pieces go in at 1 s, leaving q = 782,336 above the
        // mark, 699,050; the seventh waits at the gate until 2 s.
        let a = quiet(&[
            "--stall-peers",
            "1",
            "--stall-kbuf",
            "1052672",
            "--stall-rwnd",
            "4096",
            "--stream-piece",
            "131072",
            "--stream-gate",
            "--large-size",
            "16384",
        ]);
        let mut sim = Sim::new(&a);
        sim.run();
        let stall = sim.episodes[0].peers[0];
        assert_eq!(sim.conns[stall as usize].ended_at, Some(2 * SEC));
        let l = (0..sim.replies.len() as u32)
            .find(|&r| sim.replies[r as usize].kind == Kind::Stall)
            .unwrap();
        assert_eq!(sim.replies[l as usize].pieces, 6);
        let v = sim.report();
        assert_eq!(v["d"]["ends"]["room_timeout"]["stall"], 1);
        assert_eq!(v["large"]["episode"]["room_timeouts"], 1);
        assert_eq!(v["d"]["sends_waited_for_room"].get("stall"), None);
    }

    #[test]
    fn a_piece_waits_admit_ms_from_its_own_join() {
        // A 16-slot pool. The drainer's third piece holds 8 slots waiting for
        // room; stalled peer 0's first piece, partly sent, holds the other 8
        // until 2 s; stalled peer 1's waits and takes the drainer's 8 when its
        // third piece settles. The drainer's fourth piece then waits from that
        // moment, and times out 500 ms later, before 2 s.
        let a = quiet(&[
            "--stall-peers",
            "2",
            "--stall-gap-us",
            "1000",
            "--stall-kbuf",
            "8192",
            "--drainers",
            "1",
            "--drain-read-bps",
            "1048576",
            "--drain-kbuf",
            "262144",
            "--pool-slots",
            "16",
            "--stream-piece",
            "131072",
            "--admit-ms",
            "500",
            "--large-size",
            "16384",
        ]);
        let mut sim = Sim::new(&a);
        sim.run();
        let drain = (0..sim.replies.len() as u32)
            .find(|&r| sim.replies[r as usize].kind == Kind::Drain && sim.pieced(r))
            .unwrap();
        let last = *pieces_of(&sim, drain).last().unwrap();
        assert_eq!(last.piece, 3);
        assert_eq!(last.stage, Stage::Ended);
        assert!(last.joined_at > SEC + 100 * MS);
        let c = last.conn as usize;
        assert_eq!(sim.conns[c].ended_at, Some(last.joined_at + 500 * MS));
        assert_eq!(sim.report()["d"]["ends"]["admit_timeout"]["drain"], 1);
    }

    #[test]
    fn a_piece_is_timed_for_settle_ms_from_its_own_admission() {
        // 1 MiB to a drainer reading 96 KiB/s through a 128 KiB buffer, in
        // 64 KiB pieces: the reply takes about 10.7 s, and each piece settles
        // within 0.9 s of its admission, so none is aborted.
        let drainer = [
            "--small-conns",
            "0",
            "--warmup",
            "1",
            "--stall-peers",
            "0",
            "--drainers",
            "1",
            "--drain-size",
            "1048576",
            "--drain-read-bps",
            "98304",
            "--drain-kbuf",
            "131072",
            "--large-size",
            "16384",
            "--episode-ms",
            "16000",
            "--duration",
            "16",
        ];
        let mut more = drainer.to_vec();
        more.extend_from_slice(&["--stream-piece", "65536"]);
        let v = run_audited(&args(&more));
        assert_eq!(v["d"]["drain"]["completed"], 1);
        assert_eq!(v["large"]["episode"]["settle_aborts"], 0);
        assert!(v["d"]["drain"]["completion_us"]["max"].as_f64().unwrap() > 10e6);
        // Sent whole, it settles only when 896 KiB have been read, 9.3 s
        // after its admission.
        let v = run(&args(&drainer));
        assert_eq!(v["d"]["drain"]["completed"], 0);
        assert_eq!(v["d"]["ends"]["settle_timeout"]["drain"], 1);
    }

    #[test]
    fn stalled_peers_ask_one_gap_apart_and_the_head_one_gap_and_the_delay_after() {
        let a = quiet(&["--stall-gap-us", "40"]);
        let mut sim = Sim::new(&a);
        sim.run();
        let asked: Vec<u64> = sim
            .replies
            .iter()
            .filter(|r| r.kind == Kind::Stall)
            .map(|r| r.scheduled_at)
            .collect();
        assert_eq!(asked, [SEC, SEC + 40_000, SEC + 80_000]);
        assert_eq!(sim.episodes[0].requested_at, SEC + 120_000 + 200 * MS);
        // At 0 they ask together, and the head 200 ms after.
        let mut sim = Sim::new(&quiet(&[]));
        sim.run();
        assert!(
            sim.replies
                .iter()
                .filter(|r| r.kind == Kind::Stall)
                .all(|r| r.scheduled_at == SEC)
        );
        assert_eq!(sim.episodes[0].requested_at, SEC + 200 * MS);
    }

    #[test]
    fn the_fewest_free_slots_during_a_head_count_its_own_and_every_admission() {
        // The head takes 448 of the 512 slots once the stalled peers are
        // aborted; its 128 KiB pieces take 8 at a time.
        let v = run(&quiet(&["--stall-gap-us", "40", "--sample-ms", "10"]));
        assert_eq!(v["d"]["large"]["min_free"], 64);
        // Every sample from its request to its last byte saw the stalled
        // peers' 384 slots held, and none fell in the 6.8 ms after admission.
        assert_eq!(v["d"]["large"]["min_free_sampled"], 128);
        let v = run(&quiet(&[
            "--stall-gap-us",
            "40",
            "--stream-piece",
            "131072",
            "--stream-gate",
        ]));
        assert_eq!(v["d"]["large"]["min_free"], 504);
    }

    #[test]
    fn every_argument_is_echoed_in_the_output() {
        let params = args(&[]).params();
        for arg in Args::command().get_arguments() {
            let id = arg.get_id().as_str();
            if id != "help" {
                assert!(params.get(id).is_some(), "{id} is not echoed");
            }
        }
    }
}
