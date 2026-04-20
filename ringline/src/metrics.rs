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
pub static CONNECTIONS: ShardedCounterGroup = ShardedCounterGroup::new(2);

#[metric(name = "ringline/bytes", description = "Byte transfer counters")]
pub static BYTES: ShardedCounterGroup = ShardedCounterGroup::new(2);

#[metric(name = "ringline/ring", description = "Ring utilization counters")]
pub static RING: ShardedCounterGroup = ShardedCounterGroup::new(4);

#[metric(name = "ringline/pool", description = "Pool exhaustion counters")]
pub static POOL: ShardedCounterGroup = ShardedCounterGroup::new(3);

#[metric(name = "ringline/udp", description = "UDP counters")]
pub static UDP: ShardedCounterGroup = ShardedCounterGroup::new(3);

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
}

/// Counter slot indices for byte metrics.
pub mod bytes {
    pub const RECEIVED: usize = 0;
    pub const SENT: usize = 1;
}

/// Counter slot indices for ring utilization metrics.
pub mod ring {
    pub const CQE_PROCESSED: usize = 0;
    pub const SQE_SUBMIT_FAILURES: usize = 1;
    pub const CLOSE_SUBMIT_FAILURES: usize = 2;
    pub const RECV_ARM_FAILURES: usize = 3;
}

/// Counter slot indices for pool exhaustion metrics.
pub mod pool {
    pub const SEND_EXHAUSTED: usize = 0;
    pub const TIMER_EXHAUSTED: usize = 1;
    pub const BUFFER_RING_EMPTY: usize = 2;
}

/// Counter slot indices for UDP metrics.
pub mod udp {
    pub const DATAGRAMS_RECEIVED: usize = 0;
    pub const DATAGRAMS_SENT: usize = 1;
    pub const SEND_ERRORS: usize = 2;
}

/// Initialize per-entry metadata (labels) for all counter groups.
///
/// Call once at startup before metrics are scraped.
pub fn init_metadata() {
    CONNECTIONS.insert_metadata(conn::ACCEPTED, "op".into(), "accepted".into());
    CONNECTIONS.insert_metadata(conn::CLOSED, "op".into(), "closed".into());

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

    POOL.insert_metadata(pool::SEND_EXHAUSTED, "op".into(), "send_exhausted".into());
    POOL.insert_metadata(pool::TIMER_EXHAUSTED, "op".into(), "timer_exhausted".into());
    POOL.insert_metadata(
        pool::BUFFER_RING_EMPTY,
        "op".into(),
        "buffer_ring_empty".into(),
    );

    UDP.insert_metadata(
        udp::DATAGRAMS_RECEIVED,
        "op".into(),
        "datagrams_received".into(),
    );
    UDP.insert_metadata(udp::DATAGRAMS_SENT, "op".into(), "datagrams_sent".into());
    UDP.insert_metadata(udp::SEND_ERRORS, "op".into(), "send_errors".into());
}
