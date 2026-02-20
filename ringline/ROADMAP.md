# Ringline Roadmap

Deferred features and improvements, roughly ordered by priority.

## Backpressure / Pause Recv

Per-connection send queue limits and recv suspension. When a connection's
outbound queue exceeds a threshold, pause the multishot recv to apply
backpressure. Resume when the queue drains below a low-water mark.

## connect_addrs Memory Optimization

The `connect_addrs` Vec is pre-allocated to `max_connections` size but only
used by outbound connections. Consider lazy allocation or a smaller pool
with a free-list to reduce memory footprint for server-heavy workloads.

## TLS close_notify Timeout

After sending close_notify, force-close the connection if the peer doesn't
respond within a configurable delay. Currently the close SQE is submitted
immediately after the alert — a slow peer could delay the FIN.

## Idle Connection Timeout

Auto-close connections that have been idle (no data sent or received) for
a configurable duration. Track last-activity timestamps per connection and
use periodic timeout SQEs or on_tick checks.

## Per-Operation Timeouts

Generalize the connect timeout mechanism to support timeouts on individual
send and recv operations, not just connect.

## Splice / Zero-Copy Proxy Support

Use `io_uring` splice operations to forward data between two connections
without copying through userspace. Useful for reverse-proxy and gateway
workloads.

## Structured Metrics / Observability

Expose per-worker counters (connections accepted, bytes sent/received,
send pool utilization, buffer ring exhaustion events) via a callback or
shared-memory interface for integration with monitoring systems.
