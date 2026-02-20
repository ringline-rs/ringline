//! ringline runtime metrics.
//!
//! Per-worker counters for connections, bytes, ring utilization, and pool
//! exhaustion. Automatically exposed via Prometheus when registered with
//! the admin server.

use crate::counter::{Counter, CounterGroup};
use metriken::{Gauge, metric};

// Counter groups (sharded storage — one shard per worker, no false sharing).
static CONN: CounterGroup = CounterGroup::new();
static BYTES: CounterGroup = CounterGroup::new();
static RING: CounterGroup = CounterGroup::new();
static POOL: CounterGroup = CounterGroup::new();
static UDP: CounterGroup = CounterGroup::new();

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
}

// ── Connection lifecycle ─────────────────────────────────────────

#[metric(
    name = "ringline/connections/accepted",
    description = "Total connections accepted"
)]
pub static CONNECTIONS_ACCEPTED: Counter = Counter::new(&CONN, conn::ACCEPTED);

#[metric(
    name = "ringline/connections/closed",
    description = "Total connections closed"
)]
pub static CONNECTIONS_CLOSED: Counter = Counter::new(&CONN, conn::CLOSED);

#[metric(
    name = "ringline/connections/active",
    description = "Currently active connections"
)]
pub static CONNECTIONS_ACTIVE: Gauge = Gauge::new();

// ── Bytes ────────────────────────────────────────────────────────

#[metric(name = "ringline/bytes/received", description = "Total bytes received")]
pub static BYTES_RECEIVED: Counter = Counter::new(&BYTES, bytes::RECEIVED);

#[metric(name = "ringline/bytes/sent", description = "Total bytes sent")]
pub static BYTES_SENT: Counter = Counter::new(&BYTES, bytes::SENT);

// ── Ring utilization ─────────────────────────────────────────────

#[metric(name = "ringline/cqe/processed", description = "Total CQEs processed")]
pub static CQE_PROCESSED: Counter = Counter::new(&RING, ring::CQE_PROCESSED);

#[metric(
    name = "ringline/sqe/submit_failures",
    description = "SQE submission failures"
)]
pub static SQE_SUBMIT_FAILURES: Counter = Counter::new(&RING, ring::SQE_SUBMIT_FAILURES);

// ── Pool exhaustion ──────────────────────────────────────────────

#[metric(
    name = "ringline/pool/send_exhausted",
    description = "Send copy pool exhaustion events"
)]
pub static SEND_POOL_EXHAUSTED: Counter = Counter::new(&POOL, pool::SEND_EXHAUSTED);

#[metric(
    name = "ringline/pool/timer_exhausted",
    description = "Timer pool exhaustion events"
)]
pub static TIMER_POOL_EXHAUSTED: Counter = Counter::new(&POOL, pool::TIMER_EXHAUSTED);

#[metric(
    name = "ringline/pool/buffer_ring_empty",
    description = "Recv buffer ring empty events"
)]
pub static BUFFER_RING_EMPTY: Counter = Counter::new(&POOL, pool::BUFFER_RING_EMPTY);

// ── UDP ──────────────────────────────────────────────────────────

#[metric(
    name = "ringline/udp/datagrams_received",
    description = "Total UDP datagrams received"
)]
pub static UDP_DATAGRAMS_RECEIVED: Counter = Counter::new(&UDP, udp::DATAGRAMS_RECEIVED);

#[metric(
    name = "ringline/udp/datagrams_sent",
    description = "Total UDP datagrams sent"
)]
pub static UDP_DATAGRAMS_SENT: Counter = Counter::new(&UDP, udp::DATAGRAMS_SENT);
