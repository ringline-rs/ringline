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
pub static CONNECTIONS: ShardedCounterGroup = ShardedCounterGroup::new(8);

#[metric(name = "ringline/bytes", description = "Byte transfer counters")]
pub static BYTES: ShardedCounterGroup = ShardedCounterGroup::new(3);

#[metric(name = "ringline/ring", description = "Ring utilization counters")]
pub static RING: ShardedCounterGroup = ShardedCounterGroup::new(6);

#[metric(name = "ringline/pool", description = "Pool exhaustion counters")]
pub static POOL: ShardedCounterGroup = ShardedCounterGroup::new(9);

#[metric(
    name = "ringline/recv_ring",
    description = "TCP receive ring: the kind each worker selected, and lends refused"
)]
pub static RECV_RING: ShardedCounterGroup = ShardedCounterGroup::new(recv_ring::COUNT);

#[metric(
    name = "ringline/recv_preflight_failed",
    description = "Incremental-ring preflights that failed, by step"
)]
pub static RECV_PREFLIGHT_FAILED: ShardedCounterGroup =
    ShardedCounterGroup::new(recv_preflight::COUNT);

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

// ── Gauge (not sharded) ─────────────────────────────────────────

#[metric(
    name = "ringline/connections/active",
    description = "Currently active connections"
)]
pub static CONNECTIONS_ACTIVE: Gauge = Gauge::new();

// ── Index constants ─────────────────────────────────────────────

/// Counter slot indices for connection metrics.
pub mod conn {
    pub const ACCEPTED: usize = 0;
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
    /// Accepted connections the acceptor thread closed because every live
    /// worker's accept queue was full (`ConfigBuilder::accept_queue_capacity`).
    pub const ACCEPT_BACKLOG_DROPPED: usize = 7;
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
/// one and slot 1 is permanently unused (the enum skips it). That wastes a slot
/// and keeps the increment a plain cast with no lookup table to fall out of step
/// with the enum.
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

/// Why suppressing the `ECANCELED` re-arm did not stop offers being withdrawn.
///
/// Suppressing the re-arm left `not_offered` at 95.2% of abandonments, unchanged
/// (`docs/journal/2026-09-two-phase-park.md`). These four answer the question the
/// abandonment counters cannot: whether the cancel is submitted at all, whether
/// the suppression fires, and whether data still reaches the connection while it
/// is supposed to be draining. Between them there is only one consistent story,
/// which is the point — six hypotheses have already died here.
pub mod park_diag {
    /// `begin_park` submitted a recv-cancel, because a multishot was armed.
    pub const CANCEL_SUBMITTED: usize = 0;
    /// `begin_park` started a park with *no* cancel, because no multishot was
    /// armed. Such a park gets no suppression either, so anything still
    /// delivering keeps delivering.
    pub const CANCEL_ABSENT: usize = 1;
    /// The `ECANCELED` branch took the draining early-return and skipped both
    /// re-arms. If this is ~0 the suppression is dead code in practice.
    pub const REARM_SUPPRESSED: usize = 2;
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

    /// Number of slots.
    pub const COUNT: usize = 7;
}

/// Counter slot indices for park-abandonment reasons.
///
/// One slot per `ParkBlocker`, plus the two failures that are not blockers.
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
    /// The armed recv was not one `begin_park` could cancel.
    pub const RECV_ARM_NOT_CANCELLABLE: usize = 2;
    /// An outbound connection, which park does not move.
    pub const OUTBOUND: usize = 3;
    /// The handler's offer is no longer standing. The offer is withdrawn the
    /// moment bytes arrive and is *not* restored when the handler consumes
    /// them, so this can hold while the connection is otherwise quiescent.
    pub const NOT_OFFERED: usize = 4;
    /// A TLS session, whose transfer is unimplemented.
    pub const TLS_SESSION: usize = 5;
    /// Teardown was requested across the round trip.
    pub const CLOSING: usize = 6;
    /// Queued or in-flight sends hold this worker's pool slots.
    pub const SENDS: usize = 7;
    /// A Mode A forward write is in flight.
    pub const FORWARD_WRITE: usize = 8;
    /// A send chain has SQEs in the kernel.
    pub const CHAIN: usize = 9;
    /// A live `SegmentReader` owns the connection's delivery discipline, so
    /// there is no quiescent point at all.
    pub const SEGMENT_READER: usize = 10;
    /// A fallback recv is in flight against this worker's send pool.
    pub const RECV_FALLBACK: usize = 11;
    /// A direct-echo response is queued for the next flush.
    pub const DIRECT_ECHO: usize = 12;
    /// The slot was recycled while the install was in flight.
    pub const SLOT_RECYCLED: usize = 13;
    /// The `FixedFdInstall` failed, or the linked recv-cancel returned
    /// `ECANCELED` because the recv had self-terminated.
    pub const INSTALL_FAILED: usize = 14;

    /// Number of slots. Sizing the group from this keeps the width and the
    /// range check from drifting apart.
    pub const COUNT: usize = 15;
}

/// Counter slot indices for byte metrics.
pub mod bytes {
    pub const RECEIVED: usize = 0;
    pub const SENT: usize = 1;
    /// Bytes received via fallback one-shot recvs (also counted in
    /// `RECEIVED`); the fraction of traffic arriving through the
    /// degraded path when the provided ring is smaller than a response.
    pub const FALLBACK_RECEIVED: usize = 2;
}

/// Counter slot indices for ring utilization metrics.
pub mod ring {
    pub const CQE_PROCESSED: usize = 0;
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
}

/// Slot indices for `RECV_RING`: one count per worker by the TCP receive
/// ring it registered (`ConfigBuilder::recv_incremental`), and the lends the
/// lend cap refused.
pub mod recv_ring {
    /// An incremental ring (`IOU_PBUF_RING_INC`).
    pub const INCREMENTAL: usize = 0;
    /// A plain ring.
    pub const PLAIN: usize = 1;
    /// Completions copied instead of lent because more than half the ring's
    /// buffers had a hold, this completion's and queued releases included
    /// (`recv_incremental` only). A per-completion event, unlike the
    /// per-worker kind counts.
    pub const LEND_REFUSED: usize = 2;
    pub const COUNT: usize = 3;
}

/// Slot indices for `RECV_PREFLIGHT_FAILED`: the step of the
/// incremental-ring preflight that did not behave as the receive path
/// relies on (`backend/uring/engine/preflight.rs`). A failed preflight
/// selects a plain ring.
pub mod recv_preflight {
    /// The socketpair could not be created.
    pub const SOCKETPAIR: usize = 0;
    /// A write, read or ring operation failed.
    pub const IO_ERROR: usize = 1;
    /// A step's completion did not arrive within 1 s.
    pub const TIMEOUT: usize = 2;
    /// The first or second appended completion.
    pub const APPEND: usize = 3;
    /// The appended data or the ring entry's advance.
    pub const OFFSETS: usize = 4;
    /// The completion that uses the buffer up, or the `ENOBUFS` after it.
    pub const EXHAUSTION: usize = 5;
    /// The completion after the buffer was posted again.
    pub const REPOST: usize = 6;
    /// The half-close completion or the ring entry it leaves.
    pub const EOF: usize = 7;
    pub const COUNT: usize = 8;
}

/// Slot indices for per-`OpTag` completion counters: the slot *is* the
/// discriminant.
pub mod cqe_tag {
    /// One past the largest `OpTag` discriminant (`CloseCancel = 34`).
    ///
    /// Deliberately not derived from the enum: `ShardedCounterGroup::new` needs
    /// a const, and there is no const way to ask an enum for its maximum
    /// discriminant. `count_covers_every_tag` in the tests below fails if a new
    /// tag is added above this, which is the case that would otherwise drop
    /// completions silently.
    pub const COUNT: usize = 36;
}

/// Counter slot indices for pool exhaustion metrics.
pub mod pool {
    pub const SEND_EXHAUSTED: usize = 0;
    pub const TIMER_EXHAUSTED: usize = 1;
    pub const BUFFER_RING_EMPTY: usize = 2;
    /// A TCP send returned `-EAGAIN` from the kernel: the send buffer was
    /// full and ringline waits for room before sending the rest. High counts
    /// mean the peer is consuming bytes more slowly than the producer
    /// generates them; tune `tcp_*_buffer_size` or apply application-level
    /// backpressure.
    pub const SEND_EAGAIN: usize = 3;
    /// A connection's multishot recv completed with `ENOBUFS` and the
    /// connection was parked until provided-ring buffers are returned
    /// (see `recv_starved` in the uring driver). While parked the socket
    /// is not being drained, so the kernel receive buffer fills and the
    /// advertised TCP window closes — sustained counts with large
    /// payloads mean single responses exceed the provided ring
    /// (`ConfigBuilder::recv_buffer`) and throughput is gated on buffer
    /// recycling rather than on the wire.
    pub const RECV_PARKED: usize = 4;
    /// A fallback one-shot recv was submitted for a connection parked on
    /// ENOBUFS with a partial message accumulated — the graceful-
    /// degradation path that keeps draining the socket when a single
    /// response exceeds the provided ring.
    pub const RECV_FALLBACK: usize = 5;
    /// A connection holding received data (a `forward_to` source, a segment
    /// reader, a recv-forward or direct-echo connection) reached its hold cap
    /// (`forward_hold_cap`, lowered as `ConfigBuilder::forward_hold_cap` says)
    /// and had its multishot recv cancelled (TCP window closed) to backpressure
    /// its peer — re-armed once the hold drains below the cap. Sustained counts
    /// mean a consumer is slower than its peer for large
    /// objects; unlike `RECV_PARKED` (ENOBUFS starvation) this is *deliberate*
    /// per-connection backpressure that prevents one slow consumer from depleting
    /// the shared recv ring.
    pub const FORWARD_THROTTLED: usize = 6;
    /// A segmented reader was about to park while the `RecvAccumulator` still
    /// held bytes, and those bytes were adopted into the segment hold instead.
    ///
    /// A segmented reader only ever reads `segment_hold`, so parking with a
    /// non-empty accumulator strands those bytes permanently: the connection
    /// hangs while every other signal reads healthy — ring full, multishot
    /// live, no errors. That was #423, and it was invisible to every counter
    /// here, which is why this one exists.
    ///
    /// Entering the segmented domain adopts what is already buffered, so a
    /// non-zero count means some path reached segmented delivery without
    /// adopting. The adoption keeps a live system correct; the count is how
    /// you find out it happened.
    pub const SEGMENT_STRANDED_ADOPTED: usize = 7;
    /// A zero-copy send (`SendMsgZc`) returned `-ENOMEM`, and the rest of
    /// that send went out as plain `send`s. On Linux the usual cause is
    /// that the pages the send would pin do not fit under
    /// `RLIMIT_MEMLOCK`, which charges them from Linux 6.15; from 6.14 the
    /// rings are charged to the same limit. A process with `CAP_IPC_LOCK` in
    /// the initial user namespace is not charged.
    /// Sustained counts mean zero-copy sends are paying a failed submission
    /// and a copy: raise the memlock limit, or raise `send_zc_threshold`.
    pub const SEND_ZC_ENOMEM: usize = 8;
}

/// Counter slot indices for UDP metrics.
pub mod udp {
    pub const DATAGRAMS_RECEIVED: usize = 0;
    pub const DATAGRAMS_SENT: usize = 1;
    pub const SEND_ERRORS: usize = 2;
    /// Datagrams dropped by the runtime because the per-socket recv queue
    /// reached `Config::udp_recv_queue_capacity`. Usually means the
    /// handler future has stopped consuming (panicked, returned early,
    /// or stalled).
    pub const DATAGRAMS_DROPPED: usize = 3;
}

/// Initialize per-entry metadata (labels) for all counter groups.
///
/// Call once at startup before metrics are scraped.
pub fn init_metadata() {
    RECV_RING.insert_metadata(recv_ring::INCREMENTAL, "op".into(), "incremental".into());
    RECV_RING.insert_metadata(recv_ring::PLAIN, "op".into(), "plain".into());
    RECV_RING.insert_metadata(recv_ring::LEND_REFUSED, "op".into(), "lend_refused".into());
    for (step, name) in [
        (recv_preflight::SOCKETPAIR, "socketpair"),
        (recv_preflight::IO_ERROR, "io_error"),
        (recv_preflight::TIMEOUT, "timeout"),
        (recv_preflight::APPEND, "append"),
        (recv_preflight::OFFSETS, "offsets"),
        (recv_preflight::EXHAUSTION, "exhaustion"),
        (recv_preflight::REPOST, "repost"),
        (recv_preflight::EOF, "eof"),
    ] {
        RECV_PREFLIGHT_FAILED.insert_metadata(step, "op".into(), name.into());
    }
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
        conn::ACCEPT_BACKLOG_DROPPED,
        "op".into(),
        "accept_backlog_dropped".into(),
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
        park_diag::REARM_SUPPRESSED,
        "op".into(),
        "rearm_suppressed".into(),
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

    PARK_ABANDONED.insert_metadata(park_abandon::NOT_OPEN, "op".into(), "not_open".into());
    PARK_ABANDONED.insert_metadata(
        park_abandon::DATA_PENDING,
        "op".into(),
        "data_pending".into(),
    );
    PARK_ABANDONED.insert_metadata(
        park_abandon::RECV_ARM_NOT_CANCELLABLE,
        "op".into(),
        "recv_arm_not_cancellable".into(),
    );
    PARK_ABANDONED.insert_metadata(park_abandon::OUTBOUND, "op".into(), "outbound".into());
    PARK_ABANDONED.insert_metadata(park_abandon::NOT_OFFERED, "op".into(), "not_offered".into());
    PARK_ABANDONED.insert_metadata(park_abandon::TLS_SESSION, "op".into(), "tls_session".into());
    PARK_ABANDONED.insert_metadata(park_abandon::CLOSING, "op".into(), "closing".into());
    PARK_ABANDONED.insert_metadata(park_abandon::SENDS, "op".into(), "sends".into());
    PARK_ABANDONED.insert_metadata(
        park_abandon::FORWARD_WRITE,
        "op".into(),
        "forward_write".into(),
    );
    PARK_ABANDONED.insert_metadata(park_abandon::CHAIN, "op".into(), "chain".into());
    PARK_ABANDONED.insert_metadata(
        park_abandon::SEGMENT_READER,
        "op".into(),
        "segment_reader".into(),
    );
    PARK_ABANDONED.insert_metadata(
        park_abandon::RECV_FALLBACK,
        "op".into(),
        "recv_fallback".into(),
    );
    PARK_ABANDONED.insert_metadata(park_abandon::DIRECT_ECHO, "op".into(), "direct_echo".into());
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

    BYTES.insert_metadata(bytes::RECEIVED, "op".into(), "received".into());
    BYTES.insert_metadata(bytes::SENT, "op".into(), "sent".into());
    BYTES.insert_metadata(
        bytes::FALLBACK_RECEIVED,
        "op".into(),
        "fallback_received".into(),
    );

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
    // use (discriminant 1) are simply never registered.
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

    POOL.insert_metadata(pool::SEND_EXHAUSTED, "op".into(), "send_exhausted".into());
    POOL.insert_metadata(pool::TIMER_EXHAUSTED, "op".into(), "timer_exhausted".into());
    POOL.insert_metadata(
        pool::BUFFER_RING_EMPTY,
        "op".into(),
        "buffer_ring_empty".into(),
    );
    POOL.insert_metadata(pool::SEND_EAGAIN, "op".into(), "send_eagain".into());
    POOL.insert_metadata(pool::RECV_PARKED, "op".into(), "recv_parked".into());
    POOL.insert_metadata(pool::RECV_FALLBACK, "op".into(), "recv_fallback".into());
    POOL.insert_metadata(
        pool::FORWARD_THROTTLED,
        "op".into(),
        "forward_throttled".into(),
    );
    POOL.insert_metadata(
        pool::SEGMENT_STRANDED_ADOPTED,
        "op".into(),
        "segment_stranded_adopted".into(),
    );
    POOL.insert_metadata(pool::SEND_ZC_ENOMEM, "op".into(), "send_zc_enomem".into());

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
            conn::ACCEPT_BACKLOG_DROPPED,
        ] {
            assert!(
                CONNECTIONS.increment(idx),
                "CONNECTIONS[{idx}] out of bounds"
            );
        }
        for idx in [bytes::RECEIVED, bytes::SENT, bytes::FALLBACK_RECEIVED] {
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
            pool::BUFFER_RING_EMPTY,
            pool::SEND_EAGAIN,
            pool::RECV_PARKED,
            pool::RECV_FALLBACK,
            pool::FORWARD_THROTTLED,
            pool::SEGMENT_STRANDED_ADOPTED,
            pool::SEND_ZC_ENOMEM,
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
        for idx in [
            recv_ring::INCREMENTAL,
            recv_ring::PLAIN,
            recv_ring::LEND_REFUSED,
        ] {
            assert!(RECV_RING.increment(idx), "RECV_RING[{idx}] out of bounds");
        }
        for idx in 0..recv_preflight::COUNT {
            assert!(
                RECV_PREFLIGHT_FAILED.increment(idx),
                "RECV_PREFLIGHT_FAILED[{idx}] out of bounds"
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
        assert_eq!(op(recv_ring::INCREMENTAL).as_deref(), Some("incremental"));
        assert_eq!(op(recv_ring::PLAIN).as_deref(), Some("plain"));
        assert_eq!(op(recv_ring::LEND_REFUSED).as_deref(), Some("lend_refused"));
        for idx in 0..recv_ring::COUNT {
            assert!(
                RECV_RING
                    .load_metadata(idx)
                    .is_some_and(|m| m.contains_key("op")),
                "RECV_RING[{idx}] has no op label"
            );
        }
        for idx in 0..recv_preflight::COUNT {
            assert!(
                RECV_PREFLIGHT_FAILED
                    .load_metadata(idx)
                    .is_some_and(|m| m.contains_key("op")),
                "RECV_PREFLIGHT_FAILED[{idx}] has no op label"
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
        assert!(found >= 30, "expected the full tag set, found {found}");
    }

    /// The array is indexed by discriminant, which leaves gaps. Assert exactly
    /// which gaps we expect, rather than letting an unnoticed new one look
    /// normal — an unregistered slot reads as a counter stuck at zero.
    ///
    /// Slot 1 is skipped by the enum outright. Slot 17 (`RecvMsgMultiTs`) exists
    /// only under the `timestamps` feature, so the expected gap set is
    /// feature-dependent; this test found that the hard way.
    #[test]
    fn expected_slots_are_unused() {
        let unused: Vec<usize> = (0..cqe_tag::COUNT)
            .filter(|i| OpTag::from_u8(*i as u8).is_none())
            .collect();
        #[cfg(feature = "timestamps")]
        let expected = vec![1];
        #[cfg(not(feature = "timestamps"))]
        let expected = vec![1, 17];
        assert_eq!(
            unused, expected,
            "unexpected unused CQE_BY_TAG slots (timestamps feature changes this)"
        );
    }
}
