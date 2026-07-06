# API simplification: opaque config, sealed surface, v0.3.0

- **Status:** shipped (retrospective entry, reconstructed 2026-07-06 from commit history)
- **Span:** 2026-06-15 → 2026-06-25 · PRs #228–#235 (#236 lockfile follow-through 2026-07-03) · v0.3.0

## Goal

Shrink and harden the public API surface before the crate family accumulated more
external users, batching all the breakage into one coordinated release. The 0.2.x
surface had leaked internals: `Config` exposed dozens of `pub` fields (so
`Config::validate()` could be bypassed by direct field mutation), `TlsInfo` was a
bag of public fields, internal constants (`MAX_IOVECS`/`MAX_GUARDS`) and types
(`Worker`, `RecvBufferConfig`) were exported, error enums were exhaustively
matchable, and the send path carried dead entry points. Alongside the API work:
make CI deterministic by committing `Cargo.lock` and running everything `--locked`.

## What happened

Six PRs over ten days, then the release:

- **bd9ef95 (#228, 2026-06-15)** — the big one: `Config` made opaque. Every field
  became `pub(crate)`; `ConfigBuilder` became the only construction path, and
  `ConfigBuilder::config_mut()` was removed, so `Config::validate()` always runs
  on `build()` (`Config::default()` unchanged). Touched 46 files (~895 insertions /
  675 deletions) because every test, example, and both bench crates constructed
  configs by struct literal. During this work a split of `Config` into per-subsystem
  sub-structs was proposed and explicitly rejected — it stays an opaque flat struct
  (now policy in CLAUDE.md, "API Design Principles").
- **932b686 (#229, 2026-06-24)** — committed `Cargo.lock` (removed from
  `.gitignore`) for deterministic CI builds.
- **cb86cc0 (#230, 2026-06-24)** — every cargo invocation in `.github/workflows/ci.yml`
  (18 of them) switched to `--locked`.
- **6594094 (#231, 2026-06-24)** — send-path dead-code removal: deleted the unused
  `AsyncSendBuilder::build_await` / `submit_batch_await` (~85 lines out of
  `ringline/src/runtime/io.rs`) and unexported `MAX_IOVECS`/`MAX_GUARDS`. Deliberately
  narrow — see "Lessons" on what was *not* pruned.
- **077ebc4 (#232, 2026-06-25)** — swept the rest of the surface: `TlsInfo` fields
  went `pub(crate)` behind accessors (`protocol_version()`, `cipher_suite()`,
  `alpn_protocol() -> Option<&[u8]>`, `sni_hostname() -> Option<&str>`), `TlsConfig`
  made opaque, `Error` and `UdpSendError` marked `#[non_exhaustive]`, and
  `Worker`/`RecvBufferConfig` unexported from `ringline/src/lib.rs`.
- **17e5d7e (#233, 2026-06-25)** — tests covering the new `TlsInfo` accessors
  (+156 lines in `ringline/tests/tls_echo.rs`).
- **bd81bde (#234, 2026-06-25)** — release v0.3.0, a coordinated breaking release
  across the whole workspace: ringline 0.3.0, ringline-redis/-memcache 0.5.0, the
  ping/http/grpc/quic/h2/h3 crates 0.4.0. **8d407d5 (#235)** bumped to 0.3.1-dev
  the same day.

## Outcome

Shipped as v0.3.0 on 2026-06-25. The decisions made here persist as standing policy
in CLAUDE.md's "API Design Principles" section: no `pub` fields on public
config/value structs (builder/accessor only); `Config` stays an opaque *flat*
struct; public error enums are `#[non_exhaustive]`; breaking changes are batched
into coordinated major releases rather than dribbled out; and the surviving
send-path entry-point set (`with_data`/`with_bytes`, `send`/`send_nowait`,
`.copy()`/`.guard()`, `send_chain`, `submit_batch`/`build`) is deliberate — each
variant carries distinct semantics and is not to be merged or pruned casually.

One self-inflicted wound: the #235 dev bump changed the ringline version without
regenerating the just-committed `Cargo.lock`, so every `--locked` CI job — including
the daily scheduled run — went red starting Jun 28 with "cannot update the lock
file". Fixed by a one-line lock refresh in **cbc91d4 (#236, 2026-07-03)**.

## Lessons / open questions

- **Committing the lockfile changes the contract, immediately.** #229/#230 mean any
  version or dependency change must update `Cargo.lock` in the same commit — and the
  very next version-touching PR (#235) violated that. The rule is now spelled out in
  CLAUDE.md's build section; a release-process step covers it too.
- **Opaque-by-default was cheap to retrofit here but expensive in diff size** —
  #228's 46-file footprint is the argument for doing this before 1.0, not after.
- **Send-path consolidation beyond dead code was considered and not done.** #231
  removed only genuinely unused variants; the remaining entry points were judged a
  deliberate set (per CLAUDE.md). Whether any of them can still merge remains open,
  but the burden of proof now sits on the would-be consolidator.
