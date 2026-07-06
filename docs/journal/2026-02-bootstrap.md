# February 2026 Bootstrap: Core Runtime Import and the Protocol Client Crates

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-02-20 → 2026-02-26 · 158ac98..ed3d69c, PRs #1–#3 · releases v0.0.1, v0.0.2

## Goal

Stand up the ringline repository: import the thread-per-core io_uring runtime as a
publishable workspace, get CI and a release pipeline working, and grow a family of
protocol client crates on top of it.

## What happened

**Runtime import and v0.0.1 (Feb 20–21).** 158ac98 landed the core `ringline` crate
in one commit: 46 files, 16,378 insertions — driver, async event loop, buffer pools,
TLS, direct I/O, NVMe, examples, and a 3,120-line echo test suite. 3da2e3a added the
top-level README and GitHub Actions CI; 3a3e230 cleaned up clippy/rustfmt/audit;
d9ab450 added CLAUDE.md, CHANGELOG, and the release skill + workflows. 4fd0c60
(`release: v0.0.1`, PR #1) shipped the runtime alone — CHANGELOG.md dates it
2026-02-21.

**Client crates arrive and v0.0.2 (Feb 21).** 00b6cd6 ported krio-redis,
krio-memcache, and krio-quic from the crucible repo (per its commit message) as
`ringline-redis`, `ringline-memcache`, `ringline-quic` — 41 files, 22,647 insertions,
initially carrying protocol-resp, protocol-memcache, and ketama as workspace-local
crates. 7ade1a0 added `ringline-h3` on top of quic. The same day, 60189e7 deleted the
local protocol crates in favor of the published `resp-proto` v0.0.1 and
`memcache-proto` v0.0.1 from crates.io, and 8b8dc4d did the same for `ketama` — a
one-file Cargo.toml change that left the `ketama/` source directory in the tree,
where it still sits today as an orphaned copy. 896f4a9 added instrumented client
wrappers, zero-copy SET via `SendGuard`, and histogram metrics; d7bc2f8
(`release: v0.0.2`, PR #2) shipped it all.

**More clients (Feb 21–24).** 7185d91 added `ringline-ping`; 4442616 added kernel
SO_TIMESTAMPING behind a `timestamps` feature, and b5a4214 folded the instrumented
wrappers into the main clients. 9a921f1
added the sans-IO `ringline-h2` framing layer (5,110 insertions), a169e78
`ringline-grpc` on top of it, and e978a6e `ringline-http`, bridging h2 and a new
HTTP/1.1 path to `ConnCtx` (`ringline-http/src/client.rs`); 9706817 added streaming
response support and 750ad21 added `send_request()` to `H3Connection`.

**TLS always-on (Feb 23).** e82ce4c removed the TLS feature flag: rustls was already
default-on, and the flag cost ~47 `#[cfg(feature = "tls")]` gates across 8 source
files plus extra CI jobs. The same commit fixed the h2_google integration test by
flushing TLS control messages after `process_new_packets()`.

**Integration tests against real servers (Feb 23).** 223f88b wired public-server
tests for h2/h3 into CI (`ringline-h2/tests/public_servers.rs`,
`ringline-h3/tests/public_servers.rs`); bb54196 added round-trip tests for ping plus
ignored integration tests for redis (8) and memcache (8), with new CI
service jobs. This immediately shook out real bugs: DNS resolution had to move
outside the io_uring event loop (02bba74), and outbound connections needed a TLS
client config (0f5f8cd).

**Fire/recv pipelining (Feb 24–26).** c084d5c added the fire/recv pipelining API (`fire_get`/`fire_set`/
`fire_del` + `recv()`, 490 lines across `ringline-redis/src/lib.rs` and
`ringline-memcache/src/lib.rs`), with lazy timing and a non-panicking
`Err(NoPending)`; ed3d69c documented it, closing the arc.

## Outcome

Two releases in the first week: v0.0.1 (core runtime) and v0.0.2 (redis, memcache,
quic, h3 clients + zero-copy SET). By Feb 26 the workspace had nine crates and the
shapes that still define it: sans-IO framing layers (h2, h3, grpc), thin runtime
clients, published proto crates as external deps, always-on rustls, and the fire/recv
pipelining pattern.

## Lessons / open questions

- Public-server and real-service integration tests paid for themselves within hours
  of landing (02bba74, 30d7c9e, 0f5f8cd) — blocking DNS inside the event loop is
  exactly the kind of bug unit tests never catch.
- Feature flags have carrying costs: e82ce4c's removal of one flag deleted ~47 cfg
  gates. Defaulting a capability on and deleting the flag beat keeping both paths.
- The proto-crate extraction (60189e7, 8b8dc4d) set the lasting boundary between
  wire-format parsing (published crates) and runtime integration (this workspace) —
  though 8b8dc4d left the orphaned `ketama/` directory behind, still unresolved.
