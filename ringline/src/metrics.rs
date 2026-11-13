//! ringline runtime metrics.
//!
//! Per-worker counters for connections, bytes, ring utilization, and pool
//! exhaustion. Automatically exposed via Prometheus when registered with
//! the admin server.

use metriken::{Gauge, ShardedCounterGroup, metric};

// ── Sharded counter groups ──────────────────────────────────────

#[metric(
    name = "ringline/connections",
    description = "Connection lifecycle counters"
)]
pub static CONNECTIONS: ShardedCounterGroup = ShardedCounterGroup::new(12);

#[metric(name = "ringline/bytes", description = "Byte transfer counters")]
pub static BYTES: ShardedCounterGroup = ShardedCounterGroup::new(2);

#[metric(name = "ringline/ring", description = "Ring utilization counters")]
pub static RING: ShardedCounterGroup = ShardedCounterGroup::new(ring::COUNT);

#[metric(name = "ringline/pool", description = "Pool exhaustion counters")]
pub static POOL: ShardedCounterGroup = ShardedCounterGroup::new(7);

#[metric(
    name = "ringline/recv_ring",
    description = "TCP receive: bytes copied into receive storage"
)]
pub static RECV_RING: ShardedCounterGroup = ShardedCounterGroup::new(recv_ring::COUNT);

/// Direct receives on io_uring: into a plaintext connection's accumulator,
/// or into a TLS connection's ciphertext buffer.
#[metric(
    name = "ringline/recv_direct",
    description = "Direct receives into connection accumulators and TLS ciphertext buffers: armed, sized for a known length, bytes, stale, pooled buffers reused and allocated"
)]
pub static RECV_DIRECT: ShardedCounterGroup = ShardedCounterGroup::new(recv_direct::COUNT);

#[metric(name = "ringline/udp", description = "UDP counters")]
pub static UDP: ShardedCounterGroup = ShardedCounterGroup::new(4);

/// Why a started park did not complete (tier 3, #443).
///
/// `park_started` minus `park_completed` is a large number under load — a rate
/// sweep measured ~100% completion while the worker had headroom and ~1.6% once
/// it was CPU-saturated — and those two counters cannot say which gate closed.
/// One op per reason turns that gap into a named cause.
#[metric(
    name = "ringline/park_abandoned",
    description = "Started parks that did not complete, by reason"
)]
pub static PARK_ABANDONED: ShardedCounterGroup = ShardedCounterGroup::new(park_abandon::COUNT);

/// Receive arrival log lookups and merges (`docs/recv-arrival-times-design.md`).
#[metric(
    name = "ringline/recv_arrival",
    description = "Receive arrival log: lookups outside the log, and entries merged at the cap"
)]
pub static RECV_ARRIVAL: ShardedCounterGroup = ShardedCounterGroup::new(recv_arrival::COUNT);

// ── Gauge (not sharded) ─────────────────────────────────────────

/// Established connections, accepted or outbound, not yet torn down.
///
/// Incremented where `ConnectionState::established` is set (a plaintext
/// accept or connect; a TLS handshake completing) and decremented at
/// teardown only for a connection that was established, so a failed connect
/// or handshake moves it neither way. Same rule on both backends. A
/// connection still open when its worker exits is decremented as the worker
/// closes it; on io_uring a connection whose Close has not completed when
/// the worker's 10 s shutdown bound runs out is not: one holding a zero-copy
/// entry whose notification has not landed (#607), or one whose Close the
/// ring refused on every pass of the exit drain (#787). A parked
/// connection is decremented on the worker it leaves and incremented again
/// on the worker that adopts it.
#[metric(
    name = "ringline/connections/active",
    description = "Established connections not yet torn down"
)]
pub static CONNECTIONS_ACTIVE: Gauge = Gauge::new();

// ── Index constants ─────────────────────────────────────────────

/// Counter slot indices for connection metrics.
pub mod conn {
    /// Inbound connections that became established: a plaintext accept, or a
    /// TLS handshake that completed. Outbound connections are not counted. A
    /// parked connection counts again on the worker that adopts it
    /// (`ADOPTED` counts those adoptions).
    pub const ACCEPTED: usize = 0;
    /// Teardowns of established connections, accepted or outbound. A failed
    /// connect or TLS handshake is not a close; a connection still open when
    /// its worker exits is counted as the worker closes it, with the same
    /// io_uring exception as the gauge. A parked
    /// connection counts as a close on the worker it leaves. Same rule on
    /// both backends;
    /// `CONNECTIONS_ACTIVE` decrements under the same conditions.
    pub const CLOSED: usize = 1;
    /// Parks this worker started (tier 3, #443) — an imbalance it tried to
    /// repair by moving a connection to a less loaded worker.
    pub const PARK_STARTED: usize = 2;
    /// Parks that completed: the connection left this worker.
    ///
    /// Reported separately from `PARK_STARTED` because the difference is the
    /// interesting number. A park is abandoned whenever quiesce breaks across
    /// the fd-recovery round trip, so a large gap means the policy is picking
    /// connections that will not hold still, not that the mechanism is
    /// broken.
    pub const PARK_COMPLETED: usize = 3;
    /// Connections adopted from another worker.
    pub const ADOPTED: usize = 4;
    /// Accepted connections closed before reaching a handler because the
    /// worker's connection table was full (`ConfigBuilder::max_connections`).
    /// A connection adopted from another worker is not counted here.
    pub const ACCEPT_TABLE_FULL: usize = 5;
    /// Accepted connections closed before reaching a handler because the
    /// worker could not register the socket (the io_uring fixed-file table,
    /// or the mio poll). A connection adopted from another worker is not
    /// counted here.
    pub const ACCEPT_REGISTER_FAILED: usize = 6;
    /// The acceptor thread found every live worker's accept queue full
    /// (`ConfigBuilder::accept_queue_capacity`) and held a connection until
    /// one had room. Counted when the wait starts and once per 100 ms of it, so
    /// a wait that does not end counts 10 per second. While it waits,
    /// connections stay in the kernel's listen queue.
    pub const ACCEPT_QUEUE_FULL: usize = 7;
    /// A `shutdown_write` whose `shutdown(SHUT_WR)` failed at the socket:
    /// the Shutdown SQE's CQE on io_uring, the call's result on mio. Usually
    /// `ENOTCONN`: the socket is already in `TCP_CLOSE`, after a reset or a
    /// retransmission timeout.
    /// Nothing else changes: the write half stays `Shutdown`, and on
    /// io_uring the Close it held goes ahead.
    pub const SHUTDOWN_FAILED: usize = 8;
    /// An `accept` on the acceptor thread failed with an error that does not
    /// end the listener and is not retried at once (`EMFILE`, `ENFILE`,
    /// `ENOBUFS`, `ENOMEM`, or an errno ringline does not classify). The
    /// acceptor waits 10 ms and accepts again.
    pub const ACCEPT_ERROR_BACKOFF: usize = 9;
    /// An acceptor thread stopped because its listening socket can no longer
    /// accept (`EBADF`, `ENOTSOCK`, `EINVAL` outside shutdown). Its listener
    /// accepts nothing afterwards; the error is also written to stderr.
    pub const ACCEPTOR_STOPPED: usize = 10;
    /// TLS connections, inbound or outbound, closed because their handshake
    /// had not completed within `ConfigBuilder::tls_handshake_timeout`.
    pub const TLS_HANDSHAKE_TIMEOUT: usize = 11;
}

/// Completions processed, split by `OpTag`.
///
/// `ring/cqe_processed` is a single total, and every mechanism question about
/// per-operation cost reduces to *which* completions. A 64-byte echo costs
/// ~2.0 completions at full spread and ~0.44 concentrated, and that total is
/// consistent with recv batching, send coalescing, or both moving together —
/// the aggregate cannot distinguish them, and a measured ratio built from it
/// conflates causes.
///
/// Slot index is the `OpTag` discriminant, so the array is sized to the largest
/// one and the discriminants the enum skips are unused slots. That wastes those
/// slots and keeps the increment a plain cast with no lookup table to fall out
/// of step with the enum.
#[metric(
    name = "ringline/cqe_by_tag",
    description = "Completions processed, by operation tag"
)]
pub static CQE_BY_TAG: ShardedCounterGroup = ShardedCounterGroup::new(cqe_tag::COUNT);

#[metric(
    name = "ringline/park_diag",
    description = "Park mechanism diagnostics: did the cancel happen, did the suppression hold"
)]
pub static PARK_DIAG: ShardedCounterGroup = ShardedCounterGroup::new(park_diag::COUNT);

#[metric(
    name = "ringline/park_drain_us",
    description = "How long a park drain waited before its install went out, bucketed"
)]
pub static PARK_DRAIN_US: ShardedCounterGroup = ShardedCounterGroup::new(park_drain_us::COUNT);

/// Wall-clock buckets for a completed park drain, in microseconds.
///
/// Bucketed counter slots rather than a metriken histogram on purpose:
/// `runtime_metrics.rs` skips histograms when it walks the registry, so a
/// histogram would dump nothing and the measurement would silently not exist.
///
/// Wall time rather than ticks, because the question is where 9 ms of p99 went.
/// Park takes p50 down 43% and p99 up 4x (2.9 ms -> 12 ms), and 230 drains over
/// 58 s stalling one of 256 connections cannot account for that on their own — so
/// either drains are individually long, or the tail comes from somewhere the
/// drain merely triggers. These buckets tell those apart; a tick count could not,
/// since an event-loop iteration under saturation has no fixed duration.
pub mod park_drain_us {
    /// Under 100 us — the drain is not where the tail comes from.
    pub const LT_100: usize = 0;
    pub const LT_250: usize = 1;
    pub const LT_500: usize = 2;
    pub const LT_1MS: usize = 3;
    pub const LT_2MS: usize = 4;
    pub const LT_5MS: usize = 5;
    pub const LT_10MS: usize = 6;
    /// 10 ms or more — one drain this long would explain the p99 by itself.
    pub const GE_10MS: usize = 7;

    /// Number of buckets.
    pub const COUNT: usize = 8;

    /// The bucket an elapsed drain belongs in.
    pub fn bucket(micros: u64) -> usize {
        match micros {
            0..=99 => LT_100,
            100..=249 => LT_250,
            250..=499 => LT_500,
            500..=999 => LT_1MS,
            1_000..=1_999 => LT_2MS,
            2_000..=4_999 => LT_5MS,
            5_000..=9_999 => LT_10MS,
            _ => GE_10MS,
        }
    }
}

/// Park diagnostic counters.
///
/// The first slots show whether `begin_park` submits a cancel and whether an
/// arrival withdraws an offer while the connection drains
/// (`docs/journal/2026-09-two-phase-park.md`). Slot 2 is unused.
///
/// `OFFER_DECLINED` counts `offer_for_park` calls declined because bytes were
/// unread or the connection's reader callback was the innermost one running
/// (#669).
pub mod park_diag {
    /// `begin_park` submitted a cancel, because a receive or the hangup poll
    /// was armed.
    pub const CANCEL_SUBMITTED: usize = 0;
    /// `begin_park` started a park with no cancel, because neither a receive
    /// nor the hangup poll was armed.
    pub const CANCEL_ABSENT: usize = 1;
    // Slot 2 is unused.
    /// An offer was withdrawn while the connection was marked draining — data
    /// reached it despite the cancel. If this tracks `not_offered`, the cancel
    /// is not stopping delivery and the premise is wrong at the root.
    pub const WITHDRAW_WHILE_DRAINING: usize = 3;

    /// The install went out after a drain, which is the path phase 2 added.
    pub const INSTALL_AFTER_DRAIN: usize = 4;
    /// A drain ran out of ticks waiting for the handler to re-offer, so the
    /// connection got its recv back instead of waiting forever.
    pub const DRAIN_TIMEOUT: usize = 5;
    /// A drain was dropped because the slot had been recycled under it.
    pub const DRAIN_STALE: usize = 6;

    /// `offer_for_park` was ignored: the connection held unread bytes, or its
    /// reader callback was the innermost one running. A handler whose offers
    /// all land here is never parked.
    pub const OFFER_DECLINED: usize = 7;

    /// Number of slots.
    pub const COUNT: usize = 8;
}

/// Counter slot indices for park-abandonment reasons.
///
/// One slot per `ParkBlocker`, plus the two failures that are not blockers.
/// Slots 2, 5, 8, 10 and 11 are unused.
/// Nothing is collapsed: an earlier version grouped the variants believed
/// unreachable at the install re-check into a single `other_blocker`, and that
/// slot then absorbed 97.8% of abandonments (18,844 of 19,268 in a saturated
/// run) -- the collapse hid the entire answer behind an assumption. A slot that
/// reads zero forever costs nothing; a slot that hides a cause costs a wrong
/// conclusion.
pub mod park_abandon {
    /// Not an established, open connection any more.
    pub const NOT_OPEN: usize = 0;
    /// Bytes arrived and were not consumed.
    pub const DATA_PENDING: usize = 1;
    // Slot 2 has no blocker.
    /// An outbound connection, which park does not move.
    pub const OUTBOUND: usize = 3;
    /// The handler's offer is no longer standing. The offer is withdrawn the
    /// moment bytes arrive and is *not* restored when the handler consumes
    /// them, so this can hold while the connection is otherwise quiescent.
    pub const NOT_OFFERED: usize = 4;
    // Slot 5 has no blocker.
    /// Teardown was requested across the round trip.
    pub const CLOSING: usize = 6;
    /// Queued or in-flight sends hold this worker's pool slots.
    pub const SENDS: usize = 7;
    // Slot 8 has no blocker.
    /// A send chain has SQEs in the kernel.
    pub const CHAIN: usize = 9;
    // Slots 10 and 11 have no blocker.
    /// The slot was recycled while the install was in flight.
    pub const SLOT_RECYCLED: usize = 12;
    /// The `FixedFdInstall` failed.
    pub const INSTALL_FAILED: usize = 13;
    /// A receive, a hangup poll or a hangup peek was armed when the install
    /// completed. Arms are refused while a park is pending, so this counts
    /// a path that armed one anyway.
    pub const RECEIVE_ARMED: usize = 14;

    /// Number of slots. Sizing the group from this keeps the width and the
    /// range check from drifting apart.
    pub const COUNT: usize = 15;
}

/// Counter slot indices for byte metrics.
pub mod bytes {
    pub const RECEIVED: usize = 0;
    pub const SENT: usize = 1;
}

/// Counter slot indices for ring utilization metrics.
pub mod ring {
    pub const CQE_PROCESSED: usize = 0;
    /// An SQE push the ring refused: the submit that frees room returned an
    /// error (for example `EBUSY` while the CQ overflow list is non-empty),
    /// or the SQ was still full after it. Sends and receive arms retry a
    /// refused push every iteration (#830), so each retry that is refused
    /// again counts once more.
    pub const SQE_SUBMIT_FAILURES: usize = 1;
    pub const CLOSE_SUBMIT_FAILURES: usize = 2;
    pub const RECV_ARM_FAILURES: usize = 3;
    /// A CQE arrived with an `OpTag` that `OpTag::from_u8` doesn't
    /// recognise. Indicates either a corrupted user_data or a future
    /// reorder of the `OpTag` enum that left a stale value in flight.
    pub const CQE_UNKNOWN_TAG: usize = 4;
    /// A `Shutdown` CQE arrived for a connection slot whose generation had
    /// already moved on — the FIN was executed against the slot's *next*
    /// occupant. `try_finalize_close` now holds the `Close` that frees the slot
    /// until the `Shutdown` CQE lands, so this should stay at zero; a nonzero
    /// value means that gate leaked (#518).
    pub const SHUTDOWN_STALE: usize = 5;
    /// io_uring: reaps that found completions waiting in the kernel's
    /// overflow list because the CQ was full. They are delivered on the next
    /// enter; the count says the CQ is too small for the load.
    pub const CQ_OVERFLOW: usize = 6;
    /// io_uring: completions the kernel dropped because it could not allocate
    /// an overflow entry. Each is an operation that never completes.
    pub const CQE_DROPPED: usize = 7;
    /// io_uring: enters that returned `EBADR`, the kernel's report that
    /// completions were dropped. The worker carries on.
    pub const CQE_DROPPED_REPORTED: usize = 8;
    pub const COUNT: usize = 9;
}

/// Slot indices for `RECV_RING`: copies in the receive path.
pub mod recv_ring {
    /// Bytes copied into receive storage, on both backends: appended to or
    /// merged in a connection's accumulator (with the bytes a reallocation
    /// moves) or prepended to it, and TLS plaintext the unbuffered engine stashes when the send path
    /// decrypts it. Ciphertext staged for TLS is not counted.
    pub const BYTES_COPIED: usize = 0;
    pub const COUNT: usize = 1;
}

/// Slot indices for `RECV_DIRECT`.
pub mod recv_direct {
    /// Direct receives submitted.
    pub const ARMED: usize = 0;
    /// Of those, receives armed after the parser returned a `NeedAtLeast` of
    /// at least `recv_direct_region`, into a buffer grown to hold the rest of
    /// the message.
    pub const KNOWN_LENGTH: usize = 1;
    /// Bytes the kernel wrote into accumulators and TLS ciphertext buffers.
    pub const BYTES: usize = 2;
    /// Completions whose connection had closed or whose slot was reused.
    pub const STALE: usize = 3;
    /// Buffers a direct connection borrowed for a large message that came
    /// from the worker's free buffers.
    pub const POOL_REUSED: usize = 4;
    /// Buffers a direct connection borrowed for a large message that were
    /// allocated because no free buffer fit.
    pub const POOL_ALLOCATED: usize = 5;
    /// Connections closed because their hangup peek found the stream ended
    /// with no receive in flight and nothing buffered.
    pub const HANGUP: usize = 6;
    pub const COUNT: usize = 7;
}

/// Slot indices for `RECV_ARRIVAL`.
pub mod recv_arrival {
    /// A reader call whose range started below the oldest entry or ended
    /// past the newest end, which took the nearest entry's time, or that
    /// read an empty log, which gave no time. A call counts at most once.
    /// Bytes held out of stream order return wrong times without counting
    /// here.
    pub const CLAMPED: usize = 0;
    /// A push into a log at its 1024-entry cap, which merged the two oldest
    /// entries. The merged entry keeps the earlier time.
    pub const MERGED: usize = 1;
    pub const COUNT: usize = 2;
}

/// Slot indices for per-`OpTag` completion counters: the slot *is* the
/// discriminant.
pub mod cqe_tag {
    /// One past the largest `OpTag` discriminant (`HangupPeek = 38`).
    ///
    /// Deliberately not derived from the enum: `ShardedCounterGroup::new` needs
    /// a const, and there is no const way to ask an enum for its maximum
    /// discriminant. `count_covers_every_tag` in the tests below fails if a new
    /// tag is added above this, which is the case that would otherwise drop
    /// completions silently.
    pub const COUNT: usize = 39;
}

/// Counter slot indices for pool exhaustion metrics.
pub mod pool {
    pub const SEND_EXHAUSTED: usize = 0;
    pub const TIMER_EXHAUSTED: usize = 1;
    pub const BUFFER_RING_EMPTY: usize = 2;
    /// A stream send returned `-EAGAIN` from the kernel: the send buffer was
    /// full and ringline waits for room before sending the rest. This is
    /// ordinary backpressure, and a resubmit can count again. High counts
    /// mean the peer is consuming bytes more slowly than the producer
    /// generates them; tune `tcp_*_buffer_size` or apply application-level
    /// backpressure.
    pub const SEND_EAGAIN: usize = 3;
    /// A zero-copy send (`SendMsgZc`) returned `-ENOMEM`, and the rest of
    /// that send went out as plain `send`s. On Linux the usual cause is
    /// that the pages the send would pin do not fit under
    /// `RLIMIT_MEMLOCK`, which charges them from Linux 6.15; from 6.14 the
    /// rings are charged to the same limit. A process with `CAP_IPC_LOCK` in
    /// the initial user namespace is not charged.
    /// Sustained counts mean zero-copy sends are paying a failed submission
    /// and a copy: raise the memlock limit, or raise `send_zc_threshold`.
    pub const SEND_ZC_ENOMEM: usize = 4;
    /// A standalone task did not fit in the worker's slab of
    /// `ConfigBuilder::standalone_task_capacity` slots. `spawn` and
    /// `spawn_with_handle` return `WouldBlock`, and an `on_start` or
    /// `on_udp_bind` task is dropped.
    pub const STANDALONE_TASKS_EXHAUSTED: usize = 5;
    /// io_uring: a TLS connection closed without its close_notify because the
    /// send pool had no slot for the alert when the close was requested and
    /// still had none once the connection's own sends had drained, or the
    /// close_notify deadline forced the close first. The peer reads the
    /// stream as truncated (`eof_truncated`). The alert needs one slot. A
    /// sustained count means the pool was full at the close drain;
    /// `ConfigBuilder::send_pool` sets its size.
    pub const CLOSE_NOTIFY_DROPPED: usize = 6;
}

/// Counter slot indices for UDP metrics.
pub mod udp {
    pub const DATAGRAMS_RECEIVED: usize = 0;
    pub const DATAGRAMS_SENT: usize = 1;
    pub const SEND_ERRORS: usize = 2;
    /// Datagrams dropped by the runtime because the per-socket recv queue
    /// reached `Config::udp_recv_queue_capacity`. Usually means the
    /// handler future has stopped consuming (panicked, returned early,
    /// or stalled). On io_uring this counts only when the capacity is below
    /// the ring size. Otherwise a stalled reader stops the socket reading
    /// (`pool::BUFFER_RING_EMPTY`), and the kernel drops what does not fit in
    /// the receive buffer, which this counter does not see.
    pub const DATAGRAMS_DROPPED: usize = 3;
}

/// Initialize per-entry metadata (labels) for all counter groups.
///
/// Call once at startup before metrics are scraped.
pub fn init_metadata() {
    RECV_DIRECT.insert_metadata(recv_direct::ARMED, "op".into(), "armed".into());
    RECV_DIRECT.insert_metadata(
        recv_direct::KNOWN_LENGTH,
        "op".into(),
        "known_length".into(),
    );
    RECV_DIRECT.insert_metadata(recv_direct::BYTES, "op".into(), "bytes".into());
    RECV_DIRECT.insert_metadata(recv_direct::STALE, "op".into(), "stale".into());
    RECV_DIRECT.insert_metadata(recv_direct::POOL_REUSED, "op".into(), "pool_reused".into());
    RECV_DIRECT.insert_metadata(
        recv_direct::POOL_ALLOCATED,
        "op".into(),
        "pool_allocated".into(),
    );
    RECV_DIRECT.insert_metadata(recv_direct::HANGUP, "op".into(), "hangup".into());
    RECV_RING.insert_metadata(recv_ring::BYTES_COPIED, "op".into(), "bytes_copied".into());
    CONNECTIONS.insert_metadata(conn::ACCEPTED, "op".into(), "accepted".into());
    CONNECTIONS.insert_metadata(conn::CLOSED, "op".into(), "closed".into());
    CONNECTIONS.insert_metadata(conn::PARK_STARTED, "op".into(), "park_started".into());
    CONNECTIONS.insert_metadata(conn::PARK_COMPLETED, "op".into(), "park_completed".into());
    CONNECTIONS.insert_metadata(conn::ADOPTED, "op".into(), "adopted".into());
    CONNECTIONS.insert_metadata(
        conn::ACCEPT_TABLE_FULL,
        "op".into(),
        "accept_table_full".into(),
    );
    CONNECTIONS.insert_metadata(
        conn::ACCEPT_REGISTER_FAILED,
        "op".into(),
        "accept_register_failed".into(),
    );
    CONNECTIONS.insert_metadata(
        conn::ACCEPT_QUEUE_FULL,
        "op".into(),
        "accept_queue_full".into(),
    );
    CONNECTIONS.insert_metadata(conn::SHUTDOWN_FAILED, "op".into(), "shutdown_failed".into());
    CONNECTIONS.insert_metadata(
        conn::ACCEPT_ERROR_BACKOFF,
        "op".into(),
        "accept_error_backoff".into(),
    );
    CONNECTIONS.insert_metadata(
        conn::ACCEPTOR_STOPPED,
        "op".into(),
        "acceptor_stopped".into(),
    );
    CONNECTIONS.insert_metadata(
        conn::TLS_HANDSHAKE_TIMEOUT,
        "op".into(),
        "tls_handshake_timeout".into(),
    );

    PARK_DRAIN_US.insert_metadata(park_drain_us::LT_100, "op".into(), "lt_100us".into());
    PARK_DRAIN_US.insert_metadata(park_drain_us::LT_250, "op".into(), "lt_250us".into());
    PARK_DRAIN_US.insert_metadata(park_drain_us::LT_500, "op".into(), "lt_500us".into());
    PARK_DRAIN_US.insert_metadata(park_drain_us::LT_1MS, "op".into(), "lt_1ms".into());
    PARK_DRAIN_US.insert_metadata(park_drain_us::LT_2MS, "op".into(), "lt_2ms".into());
    PARK_DRAIN_US.insert_metadata(park_drain_us::LT_5MS, "op".into(), "lt_5ms".into());
    PARK_DRAIN_US.insert_metadata(park_drain_us::LT_10MS, "op".into(), "lt_10ms".into());
    PARK_DRAIN_US.insert_metadata(park_drain_us::GE_10MS, "op".into(), "ge_10ms".into());

    PARK_DIAG.insert_metadata(
        park_diag::CANCEL_SUBMITTED,
        "op".into(),
        "cancel_submitted".into(),
    );
    PARK_DIAG.insert_metadata(
        park_diag::CANCEL_ABSENT,
        "op".into(),
        "cancel_absent".into(),
    );
    PARK_DIAG.insert_metadata(
        park_diag::WITHDRAW_WHILE_DRAINING,
        "op".into(),
        "withdraw_while_draining".into(),
    );
    PARK_DIAG.insert_metadata(
        park_diag::INSTALL_AFTER_DRAIN,
        "op".into(),
        "install_after_drain".into(),
    );
    PARK_DIAG.insert_metadata(
        park_diag::DRAIN_TIMEOUT,
        "op".into(),
        "drain_timeout".into(),
    );
    PARK_DIAG.insert_metadata(park_diag::DRAIN_STALE, "op".into(), "drain_stale".into());
    PARK_DIAG.insert_metadata(
        park_diag::OFFER_DECLINED,
        "op".into(),
        "offer_declined".into(),
    );

    RECV_ARRIVAL.insert_metadata(recv_arrival::CLAMPED, "op".into(), "clamped".into());
    RECV_ARRIVAL.insert_metadata(recv_arrival::MERGED, "op".into(), "merged".into());

    PARK_ABANDONED.insert_metadata(park_abandon::NOT_OPEN, "op".into(), "not_open".into());
    PARK_ABANDONED.insert_metadata(
        park_abandon::DATA_PENDING,
        "op".into(),
        "data_pending".into(),
    );
    PARK_ABANDONED.insert_metadata(park_abandon::OUTBOUND, "op".into(), "outbound".into());
    PARK_ABANDONED.insert_metadata(park_abandon::NOT_OFFERED, "op".into(), "not_offered".into());
    PARK_ABANDONED.insert_metadata(park_abandon::CLOSING, "op".into(), "closing".into());
    PARK_ABANDONED.insert_metadata(park_abandon::SENDS, "op".into(), "sends".into());
    PARK_ABANDONED.insert_metadata(park_abandon::CHAIN, "op".into(), "chain".into());
    PARK_ABANDONED.insert_metadata(
        park_abandon::SLOT_RECYCLED,
        "op".into(),
        "slot_recycled".into(),
    );
    PARK_ABANDONED.insert_metadata(
        park_abandon::INSTALL_FAILED,
        "op".into(),
        "install_failed".into(),
    );
    PARK_ABANDONED.insert_metadata(
        park_abandon::RECEIVE_ARMED,
        "op".into(),
        "receive_armed".into(),
    );

    BYTES.insert_metadata(bytes::RECEIVED, "op".into(), "received".into());
    BYTES.insert_metadata(bytes::SENT, "op".into(), "sent".into());

    RING.insert_metadata(ring::CQE_PROCESSED, "op".into(), "cqe_processed".into());
    RING.insert_metadata(
        ring::SQE_SUBMIT_FAILURES,
        "op".into(),
        "sqe_submit_failures".into(),
    );
    RING.insert_metadata(
        ring::CLOSE_SUBMIT_FAILURES,
        "op".into(),
        "close_submit_failures".into(),
    );
    RING.insert_metadata(
        ring::RECV_ARM_FAILURES,
        "op".into(),
        "recv_arm_failures".into(),
    );

    // Names come from `OpTag::as_str` rather than a table here, so a new tag
    // cannot be added with its counter left unlabelled. Slots the enum does not
    // use are never registered.
    for v in 0..=u8::MAX {
        if let Some(tag) = crate::completion::OpTag::from_u8(v) {
            let slot = v as usize;
            if slot < cqe_tag::COUNT {
                CQE_BY_TAG.insert_metadata(slot, "op".into(), tag.as_str().into());
            }
        }
    }
    RING.insert_metadata(ring::CQE_UNKNOWN_TAG, "op".into(), "cqe_unknown_tag".into());
    RING.insert_metadata(ring::SHUTDOWN_STALE, "op".into(), "shutdown_stale".into());
    RING.insert_metadata(ring::CQ_OVERFLOW, "op".into(), "cq_overflow".into());
    RING.insert_metadata(ring::CQE_DROPPED, "op".into(), "cqe_dropped".into());
    RING.insert_metadata(
        ring::CQE_DROPPED_REPORTED,
        "op".into(),
        "cqe_dropped_reported".into(),
    );

    POOL.insert_metadata(pool::SEND_EXHAUSTED, "op".into(), "send_exhausted".into());
    POOL.insert_metadata(pool::TIMER_EXHAUSTED, "op".into(), "timer_exhausted".into());
    POOL.insert_metadata(
        pool::STANDALONE_TASKS_EXHAUSTED,
        "op".into(),
        "standalone_tasks_exhausted".into(),
    );
    POOL.insert_metadata(
        pool::BUFFER_RING_EMPTY,
        "op".into(),
        "buffer_ring_empty".into(),
    );
    POOL.insert_metadata(pool::SEND_EAGAIN, "op".into(), "send_eagain".into());
    POOL.insert_metadata(pool::SEND_ZC_ENOMEM, "op".into(), "send_zc_enomem".into());
    POOL.insert_metadata(
        pool::CLOSE_NOTIFY_DROPPED,
        "op".into(),
        "close_notify_dropped".into(),
    );

    UDP.insert_metadata(
        udp::DATAGRAMS_RECEIVED,
        "op".into(),
        "datagrams_received".into(),
    );
    UDP.insert_metadata(udp::DATAGRAMS_SENT, "op".into(), "datagrams_sent".into());
    UDP.insert_metadata(udp::SEND_ERRORS, "op".into(), "send_errors".into());
    UDP.insert_metadata(
        udp::DATAGRAMS_DROPPED,
        "op".into(),
        "datagrams_dropped".into(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each `conn` index names its own slot, and together they fill
    /// `CONNECTIONS`, so two counters cannot share a slot.
    #[test]
    fn conn_indices_are_distinct_and_fill_the_group() {
        let mut idx = [
            conn::ACCEPTED,
            conn::CLOSED,
            conn::PARK_STARTED,
            conn::PARK_COMPLETED,
            conn::ADOPTED,
            conn::ACCEPT_TABLE_FULL,
            conn::ACCEPT_REGISTER_FAILED,
            conn::ACCEPT_QUEUE_FULL,
            conn::SHUTDOWN_FAILED,
            conn::ACCEPT_ERROR_BACKOFF,
            conn::ACCEPTOR_STOPPED,
            conn::TLS_HANDSHAKE_TIMEOUT,
        ];
        idx.sort_unstable();
        assert_eq!(idx.to_vec(), (0..idx.len()).collect::<Vec<_>>());
        assert_eq!(
            CONNECTIONS.entries(),
            idx.len(),
            "CONNECTIONS is not sized to its named slots"
        );
    }

    /// Every declared slot index must be in bounds for its group —
    /// `ShardedCounterGroup::increment` silently returns `false` on an
    /// out-of-range index, so an undersized group means a counter that
    /// never counts (this caught `RING` sized 4 with 5 declared slots).
    #[test]
    fn declared_indices_are_in_bounds() {
        for idx in [
            conn::ACCEPTED,
            conn::CLOSED,
            conn::PARK_STARTED,
            conn::PARK_COMPLETED,
            conn::ADOPTED,
            conn::ACCEPT_TABLE_FULL,
            conn::ACCEPT_REGISTER_FAILED,
            conn::ACCEPT_QUEUE_FULL,
            conn::SHUTDOWN_FAILED,
            conn::ACCEPT_ERROR_BACKOFF,
            conn::ACCEPTOR_STOPPED,
            conn::TLS_HANDSHAKE_TIMEOUT,
        ] {
            assert!(
                CONNECTIONS.increment(idx),
                "CONNECTIONS[{idx}] out of bounds"
            );
        }
        for idx in [bytes::RECEIVED, bytes::SENT] {
            assert!(BYTES.increment(idx), "BYTES[{idx}] out of bounds");
        }
        for idx in [
            ring::CQE_PROCESSED,
            ring::SQE_SUBMIT_FAILURES,
            ring::CLOSE_SUBMIT_FAILURES,
            ring::RECV_ARM_FAILURES,
            ring::CQE_UNKNOWN_TAG,
            ring::SHUTDOWN_STALE,
        ] {
            assert!(RING.increment(idx), "RING[{idx}] out of bounds");
        }
        for idx in [
            pool::SEND_EXHAUSTED,
            pool::TIMER_EXHAUSTED,
            pool::STANDALONE_TASKS_EXHAUSTED,
            pool::BUFFER_RING_EMPTY,
            pool::SEND_EAGAIN,
            pool::SEND_ZC_ENOMEM,
            pool::CLOSE_NOTIFY_DROPPED,
        ] {
            assert!(POOL.increment(idx), "POOL[{idx}] out of bounds");
        }
        for idx in [
            udp::DATAGRAMS_RECEIVED,
            udp::DATAGRAMS_SENT,
            udp::SEND_ERRORS,
            udp::DATAGRAMS_DROPPED,
        ] {
            assert!(UDP.increment(idx), "UDP[{idx}] out of bounds");
        }
        assert!(
            RECV_RING.increment(recv_ring::BYTES_COPIED),
            "RECV_RING[{}] out of bounds",
            recv_ring::BYTES_COPIED
        );
        for idx in [recv_arrival::CLAMPED, recv_arrival::MERGED] {
            assert!(
                RECV_ARRIVAL.increment(idx),
                "RECV_ARRIVAL[{idx}] out of bounds"
            );
        }
    }

    /// Every slot of the receive-ring groups is labelled, so an exporter
    /// can name what it counts.
    #[test]
    fn recv_ring_slots_are_labelled() {
        init_metadata();
        let op = |idx| {
            RECV_RING
                .load_metadata(idx)
                .and_then(|m| m.get("op").cloned())
        };
        assert_eq!(op(recv_ring::BYTES_COPIED).as_deref(), Some("bytes_copied"));
        for idx in 0..recv_ring::COUNT {
            assert!(
                RECV_RING
                    .load_metadata(idx)
                    .is_some_and(|m| m.contains_key("op")),
                "RECV_RING[{idx}] has no op label"
            );
        }
        for idx in 0..recv_arrival::COUNT {
            assert!(
                RECV_ARRIVAL
                    .load_metadata(idx)
                    .is_some_and(|m| m.contains_key("op")),
                "RECV_ARRIVAL[{idx}] has no op label"
            );
        }
    }
}

#[cfg(test)]
mod park_drain_bucket_tests {
    use super::park_drain_us as pd;

    /// Boundaries, because an off-by-one here silently misattributes the tail —
    /// the whole point is telling "drains are sub-millisecond" from "a drain is
    /// the 9 ms".
    #[test]
    fn buckets_split_where_they_say_they_do() {
        assert_eq!(pd::bucket(0), pd::LT_100);
        assert_eq!(pd::bucket(99), pd::LT_100);
        assert_eq!(pd::bucket(100), pd::LT_250);
        assert_eq!(pd::bucket(249), pd::LT_250);
        assert_eq!(pd::bucket(250), pd::LT_500);
        assert_eq!(pd::bucket(999), pd::LT_1MS);
        assert_eq!(pd::bucket(1_000), pd::LT_2MS);
        assert_eq!(pd::bucket(4_999), pd::LT_5MS);
        assert_eq!(pd::bucket(5_000), pd::LT_10MS);
        assert_eq!(pd::bucket(9_999), pd::LT_10MS);
        assert_eq!(pd::bucket(10_000), pd::GE_10MS);
        assert_eq!(pd::bucket(u64::MAX), pd::GE_10MS);
        // every bucket in range
        for us in [0u64, 100, 250, 500, 1_000, 2_000, 5_000, 10_000] {
            assert!(pd::bucket(us) < pd::COUNT);
        }
    }
}

#[cfg(test)]
mod cqe_tag_tests {
    use super::cqe_tag;
    use crate::completion::OpTag;

    /// `cqe_tag::COUNT` sizes the counter array and the increment indexes it by
    /// raw discriminant, so a tag above `COUNT` would push completions into a
    /// slot that does not exist. `ShardedCounterGroup::increment` returns false
    /// for an out-of-range slot rather than panicking, so the failure mode is a
    /// counter that silently stays at zero — indistinguishable from "that
    /// operation never ran", which is precisely the reading this metric exists
    /// to make trustworthy.
    #[test]
    fn count_covers_every_tag() {
        let mut max = 0usize;
        let mut found = 0usize;
        for v in 0..=u8::MAX {
            if OpTag::from_u8(v).is_some() {
                max = max.max(v as usize);
                found += 1;
            }
        }
        assert!(
            max < cqe_tag::COUNT,
            "OpTag discriminant {max} needs cqe_tag::COUNT > {max}, but it is {}",
            cqe_tag::COUNT
        );
        // Guard against the walk finding nothing and passing vacuously.
        assert!(found >= 26, "expected the full tag set, found {found}");
    }

    /// The array is indexed by discriminant, which leaves gaps. Assert exactly
    /// which gaps we expect, rather than letting an unnoticed new one look
    /// normal — an unregistered slot reads as a counter stuck at zero.
    ///
    /// Slots 0, 1, 9, 11, 12, 17, 20, 25 to 30 have no `OpTag` variant.
    #[test]
    fn expected_slots_are_unused() {
        let unused: Vec<usize> = (0..cqe_tag::COUNT)
            .filter(|i| OpTag::from_u8(*i as u8).is_none())
            .collect();
        assert_eq!(
            unused,
            vec![0, 1, 9, 11, 12, 17, 20, 25, 26, 27, 28, 29, 30],
            "unexpected unused CQE_BY_TAG slots"
        );
    }
}
