# Adaptive Recv Buffering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make recv buffer geometry adapt to the workload so the concurrency/large-response throughput cliff disappears with no caller tuning, preserving every recv API's copy-count.

**Architecture:** A per-worker `RecvBufferProvider` behind which three implementations live (INC ring on kernel ≥ 6.11, adaptive size-class rings on 6.0–6.10, adaptive shared scratch on mio). A pure `SizingPolicy` unit (EWMA + `NeedAtLeast` + hysteresis) drives per-connection class selection on the size-class path and aggregate sizing on mio. An internal per-connection buffer-domain (`CopyOrConsume` / `Forward`) pins the provider/arming.

**Tech Stack:** Rust, io-uring 0.7 (`IOU_PBUF_RING_INC`, kernel 6.11+), mio, the existing `ProvidedBufRing`/`RecvAccumulator`/`ConnectionTable`.

**Reference:** `docs/recv-buffer-adaptive-design.md` (approved spec).

---

## Environment & validation rules (read first)

- **This host (macOS) builds and tests only the mio backend.** io_uring code cannot be type-checked here. Per `CLAUDE.md`, io_uring is validated on hv01 (`10.1.0.1`, kernel 6.12, 64c) or Linux CI.
- **Sync-to-hv01 loop:** `rsync -a --delete --exclude target --exclude .git <repo>/ 10.1.0.1:ringline-work/` then run cargo there. Beware piped exit codes (`$pipestatus`).
- **Always run before committing** (both backends): `cargo fmt --all`; `cargo clippy --all-targets -- -D warnings`; `cargo clippy --all-targets --features force-mio -- -D warnings`. `Cargo.lock` is committed and CI is `--locked`.
- **Phase 0 gates the io_uring provider phases (3, 4).** Do not finalize INC-provider internals before Phase 0's prototype resolves the buffer geometry and the concurrent-region-handout question. This is a spec requirement, not optional sequencing.
- Work branch already exists: `adaptive-recv-buffering` (spec committed there).

## File structure

| Path | Responsibility | Status |
|---|---|---|
| `ringline/src/recv/sizing.rs` | Pure `SizingPolicy` (EWMA + hint + hysteresis → target size / class). No I/O. | Create |
| `ringline/src/recv/domain.rs` | `RecvDomain` enum (`CopyOrConsume`/`Forward`) + per-connection storage. | Create |
| `ringline/src/recv/provider.rs` | `RecvBufferProvider` trait + `RecvView`. | Create |
| `ringline/src/recv/mod.rs` | Module wiring; re-exports. | Create |
| `ringline/src/backend/uring/provided.rs` | Today's `ProvidedBufRing` → classic size-class provider impl. | Modify |
| `ringline/src/backend/uring/provided_inc.rs` | INC provider impl (kernel ≥ 6.11). | Create |
| `ringline/src/backend/uring/ring.rs` | INC register probe; arm/re-arm against a chosen bgid. | Modify |
| `ringline/src/backend/uring/driver.rs` | Hold provider set; per-connection domain + policy state. | Modify |
| `ringline/src/backend/uring/event_loop.rs` | Route recv CQEs through the provider; feed policy from `NeedAtLeast`/observed sizes. | Modify |
| `ringline/src/backend/mio/event_loop.rs` | Adaptive shared recv scratch. | Modify |
| `ringline/src/config.rs` | Reinterpret `recv_buffer(..)` as override/cap; add opaque INC/size-class knobs. | Modify |
| `ringline/benches/` or `ringline/examples/ring_fill_bench.rs` | Promote the sweep harness; add mixed-workload mode. | Create |

Splitting the recv machinery into a `recv/` module keeps `SizingPolicy`, `RecvDomain`, and the provider interface as small, independently-testable units rather than growing `driver.rs`/`event_loop.rs` further (both already large).

---

## Phase 0: de-risk + measurement harness (gates Phases 3–4)

**Purpose:** promote the throughput bench into the repo, and answer the one question that shapes the INC provider — does few-large-buffers starve parallelism under fan-in? Output is a short findings note + chosen INC geometry, written into the spec's "Parameters" section.

### Task 0.1: Promote the ring-fill bench with a mixed-workload mode

**Files:**
- Create: `ringline/examples/ring_fill_bench.rs` (from the scratch harness used in the review; add `MODE=mixed` interleaving small and large responses per connection)

- [ ] **Step 1: Write the bench** — in-process std-thread TCP echo peer + ringline client (1 worker), env knobs `MSG_SIZE`, `CONNS`, `SECS`, `RING`, `BUF`, `MODE=whole|bytes|drain|mixed`, `PORT`. Report throughput plus `POOL::RECV_PARKED`, `POOL::RECV_FALLBACK`, `BYTES::FALLBACK_RECEIVED`, `POOL::BUFFER_RING_EMPTY` via `metrics::*::value(idx)`. `MODE=mixed`: each round randomly (index-derived, not `rand`) picks a small (8 KB) or large (256 KB) response so one connection sees both.

- [ ] **Step 2: Build on hv01** — `rsync` then `ssh 10.1.0.1 'cd ringline-work && cargo build --release --example ring_fill_bench'`. Expected: builds clean.

- [ ] **Step 3: Commit** — `git add ringline/examples/ring_fill_bench.rs && git commit -m "test: ring-fill recv bench harness with mixed-workload mode"`

### Task 0.2: INC concurrent-region-handout prototype

**Files:**
- Create: throwaway probe under the hv01 work dir (NOT committed) that registers a buf ring with `IOU_PBUF_RING_INC` and arms multishot recv across N connections, logging CQE `bid`/offset/len distribution.

- [ ] **Step 1:** On hv01, register an INC ring (`register_buf_ring_with_flags(..., IOU_PBUF_RING_INC)`) and drive the mixed bench against it with a small buffer count and large buffer size; capture whether concurrent connections' recvs draw from distinct buffers or serialize on one.
- [ ] **Step 2:** Sweep `buf_size ∈ {64K,128K,256K,512K,1M} × depth` × concurrency {8,32,128} × `MODE=mixed`; record throughput + parking + per-buffer contention.
- [ ] **Step 3:** Write findings + chosen default (INC buffer size, depth, and whether "several medium" beats "few large") into `docs/recv-buffer-adaptive-design.md` under "Parameters TBD-by-sweep", replacing the TBD. Commit that doc edit.

**Decision gate:** Phases 3–4 proceed using the geometry chosen here.

---

## Phase 1: `SizingPolicy` (pure, host-testable — full TDD)

### Task 1.1: EWMA + hint + hysteresis target sizing

**Files:**
- Create: `ringline/src/recv/sizing.rs`
- Create: `ringline/src/recv/mod.rs` (with `pub(crate) mod sizing;`)
- Modify: `ringline/src/lib.rs` (add `pub(crate) mod recv;`)

- [ ] **Step 1: Write the failing tests**

```rust
// ringline/src/recv/sizing.rs
#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SizingPolicy {
        // min 4 KiB, max 512 KiB, alpha = 0.25, downshift band = 0.5
        SizingPolicy::new(SizingConfig {
            min: 4 * 1024,
            max: 512 * 1024,
            alpha_num: 1,
            alpha_den: 4,
            downshift_num: 1,
            downshift_den: 2,
        })
    }

    #[test]
    fn starts_at_min() {
        assert_eq!(policy().target(), 4 * 1024);
    }

    #[test]
    fn sustained_large_raises_target() {
        let mut p = policy();
        for _ in 0..20 {
            p.observe(200 * 1024);
        }
        assert!(p.target() >= 128 * 1024, "target was {}", p.target());
    }

    #[test]
    fn hint_bumps_immediately() {
        let mut p = policy();
        p.hint(300 * 1024);
        assert!(p.target() >= 300 * 1024);
    }

    #[test]
    fn target_clamped_to_max() {
        let mut p = policy();
        p.hint(10 * 1024 * 1024);
        assert_eq!(p.target(), 512 * 1024);
    }

    #[test]
    fn brief_dip_does_not_downshift() {
        let mut p = policy();
        for _ in 0..20 {
            p.observe(200 * 1024);
        }
        let high = p.target();
        p.observe(1024); // one small sample
        assert_eq!(p.target(), high, "single dip should not downshift");
    }

    #[test]
    fn sustained_dip_downshifts() {
        let mut p = policy();
        for _ in 0..20 {
            p.observe(200 * 1024);
        }
        for _ in 0..40 {
            p.observe(1024);
        }
        assert!(p.target() < 128 * 1024, "target was {}", p.target());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p ringline recv::sizing`
Expected: FAIL (types not defined).

- [ ] **Step 3: Implement**

```rust
// ringline/src/recv/sizing.rs
//! Pure per-connection recv-size policy: an EWMA of observed arrival sizes plus
//! proactive `NeedAtLeast` hints, converted to a target buffer size with
//! hysteresis so a class change cannot flap on a single sample. No I/O.

/// Configuration for [`SizingPolicy`]. Fixed-point alpha/downshift avoid float
/// determinism concerns and are cheap on the hot path.
#[derive(Clone, Copy)]
pub(crate) struct SizingConfig {
    pub min: usize,
    pub max: usize,
    /// EWMA smoothing factor alpha = alpha_num / alpha_den (0 < alpha <= 1).
    pub alpha_num: u32,
    pub alpha_den: u32,
    /// Downshift only when the EWMA falls below current_target * (down_num/down_den).
    pub downshift_num: u32,
    pub downshift_den: u32,
}

pub(crate) struct SizingPolicy {
    cfg: SizingConfig,
    /// EWMA of observed sizes, in bytes.
    ewma: usize,
    /// Current target buffer size (bytes), moved with hysteresis.
    target: usize,
}

impl SizingPolicy {
    pub fn new(cfg: SizingConfig) -> Self {
        SizingPolicy {
            ewma: cfg.min,
            target: cfg.min,
            cfg,
        }
    }

    /// Record an observed arrival/message size and re-evaluate the target.
    pub fn observe(&mut self, size: usize) {
        // ewma += alpha * (size - ewma), fixed-point.
        let a_n = self.cfg.alpha_num as usize;
        let a_d = self.cfg.alpha_den as usize;
        if size >= self.ewma {
            self.ewma += (size - self.ewma) * a_n / a_d;
        } else {
            self.ewma -= (self.ewma - size) * a_n / a_d;
        }
        self.reconcile();
    }

    /// A parser hint that at least `need` more bytes are coming: bump the target
    /// immediately (proactive), without waiting for the EWMA to catch up.
    pub fn hint(&mut self, need: usize) {
        let want = need.clamp(self.cfg.min, self.cfg.max);
        if want > self.target {
            self.target = want;
        }
    }

    /// Current target buffer size in bytes, clamped to [min, max].
    pub fn target(&self) -> usize {
        self.target
    }

    fn reconcile(&mut self) {
        let ewma = self.ewma.clamp(self.cfg.min, self.cfg.max);
        if ewma > self.target {
            // Upshift immediately toward demand.
            self.target = ewma;
        } else {
            // Downshift only past the hysteresis band.
            let band = self.target * self.cfg.downshift_num as usize
                / self.cfg.downshift_den as usize;
            if ewma < band {
                self.target = ewma.max(self.cfg.min);
            }
        }
    }
}
```

- [ ] **Step 4: Run to verify pass**

Run: `cargo test -p ringline recv::sizing`
Expected: PASS (6 tests).

- [ ] **Step 5: Lint + commit**

Run: `cargo fmt --all && cargo clippy --all-targets -- -D warnings`
```bash
git add ringline/src/recv/sizing.rs ringline/src/recv/mod.rs ringline/src/lib.rs
git commit -m "feat(recv): pure SizingPolicy (EWMA + hint + hysteresis)"
```

### Task 1.2: Map a target size to a size class

**Files:**
- Modify: `ringline/src/recv/sizing.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn class_for_picks_smallest_class_ge_target() {
    // classes: 4K, 64K, 512K
    let classes = [4 * 1024, 64 * 1024, 512 * 1024];
    assert_eq!(class_index_for(&classes, 3 * 1024), 0);
    assert_eq!(class_index_for(&classes, 4 * 1024), 0);
    assert_eq!(class_index_for(&classes, 5 * 1024), 1);
    assert_eq!(class_index_for(&classes, 600 * 1024), 2); // clamps to largest
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p ringline recv::sizing::tests::class_for_picks` → FAIL.

- [ ] **Step 3: Implement**

```rust
/// Index of the smallest class whose buffer size is >= `target`, clamped to the
/// largest class. `classes` must be ascending and non-empty.
pub(crate) fn class_index_for(classes: &[usize], target: usize) -> usize {
    classes
        .iter()
        .position(|&c| c >= target)
        .unwrap_or(classes.len() - 1)
}
```

- [ ] **Step 4: Run to verify pass** — `cargo test -p ringline recv::sizing` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(recv): class_index_for target->class mapping"`

---

## Phase 2: buffer-domain type + provider trait (host-testable surface)

### Task 2.1: `RecvDomain` enum

**Files:**
- Create: `ringline/src/recv/domain.rs`
- Modify: `ringline/src/recv/mod.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_is_copy_or_consume() {
        assert_eq!(RecvDomain::default(), RecvDomain::CopyOrConsume);
    }
    #[test]
    fn forward_is_not_inc_eligible() {
        assert!(!RecvDomain::Forward.inc_eligible());
        assert!(RecvDomain::CopyOrConsume.inc_eligible());
    }
}
```

- [ ] **Step 2: Run to verify failure** — `cargo test -p ringline recv::domain` → FAIL.

- [ ] **Step 3: Implement**

```rust
// ringline/src/recv/domain.rs
//! Internal per-connection recv buffer-domain. Pins which provider/arming a
//! connection uses. Coarse by design: with_data / with_bytes / set_recv_sink
//! all share `CopyOrConsume` (they do not hold the provided buffer across
//! polls), so mixing them on one connection is allowed. Only `Forward` (the
//! long-hold recv_forward/splice path) is a distinct domain.

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum RecvDomain {
    #[default]
    CopyOrConsume,
    Forward,
}

impl RecvDomain {
    /// Whether this domain may use incremental (INC) provided buffers.
    /// Only the non-holding domain qualifies.
    pub fn inc_eligible(self) -> bool {
        matches!(self, RecvDomain::CopyOrConsume)
    }
}
```

- [ ] **Step 4: Run to verify pass** — `cargo test -p ringline recv::domain` → PASS.
- [ ] **Step 5: Commit** — `git commit -am "feat(recv): internal RecvDomain buffer-domain type"`

### Task 2.2: `RecvBufferProvider` trait + `RecvView`

**Files:**
- Create: `ringline/src/recv/provider.rs`
- Modify: `ringline/src/recv/mod.rs`

- [ ] **Step 1: Define the trait** (no test — it's an interface; the impls in Phases 3–5 carry the tests). Define exactly:

```rust
// ringline/src/recv/provider.rs
//! Abstraction over the per-worker recv buffer strategy. Implementations:
//! classic size-class rings (`backend/uring/provided.rs`), INC ring
//! (`backend/uring/provided_inc.rs`), and the mio shared scratch. Keeps the
//! event loop from branching on kernel version / API inline.

use crate::recv::domain::RecvDomain;

/// A resolved recv completion: where the freshly-received bytes live and the
/// bookkeeping token needed to release/advance them. Semantics are per-impl:
/// classic returns a whole-buffer `bid`; INC returns `bid` + `offset`.
pub(crate) struct RecvView<'a> {
    pub data: &'a [u8],
    pub release: ReleaseToken,
}

#[derive(Clone, Copy)]
pub(crate) enum ReleaseToken {
    /// Classic provided buffer: replenish this whole bid when consumed.
    Bid(u16),
    /// INC buffer region: commit `len` consumed from `bid` at `offset`.
    IncRegion { bid: u16, offset: u32, len: u32 },
    /// mio scratch: nothing to release.
    None,
}

pub(crate) trait RecvBufferProvider {
    /// Arm (or re-arm) recv for `conn_index` in `domain`, sizing to
    /// `target_bytes`. Returns Err on submit failure (caller backpressures).
    fn arm(&mut self, conn_index: u32, domain: RecvDomain, target_bytes: usize)
        -> std::io::Result<()>;

    /// Release a consumed view back to the provider.
    fn release(&mut self, token: ReleaseToken);
}
```

- [ ] **Step 2: Build (mio host)** — `cargo build -p ringline` → compiles (unused-until-wired warnings are fine; add `#[allow(dead_code)]` on items not yet consumed, removed as Phases 3–5 wire them).
- [ ] **Step 3: Commit** — `git commit -am "feat(recv): RecvBufferProvider trait + RecvView"`

---

## Phase 3: size-class provider (io_uring — validated on hv01, geometry from Phase 0)

> Internals follow the existing `ProvidedBufRing` pattern (`backend/uring/provided.rs`, `ring.rs:130-201`). Because this is io_uring code, each task's verification runs on hv01/CI, not this host. The size-class set comes from Phase 0.

### Task 3.1: Multi-class provided ring set

**Files:**
- Modify: `ringline/src/backend/uring/provided.rs` (generalize `ProvidedBufRing` to a `SizeClassRings` holding one ring per class, each with a distinct `bgid`)
- Modify: `ringline/src/backend/uring/ring.rs` (`submit_multishot_recv` takes a `bgid` argument)
- Modify: `ringline/src/backend/uring/driver.rs` (own the `SizeClassRings`; per-connection current class + `SizingPolicy`)

- [ ] **Step 1:** Add a Rust unit test in `provided.rs` (host-compilable — pure ring math, no syscalls) asserting each class ring's mask/size/`bgid` are distinct and power-of-two, mirroring the existing `ProvidedBufRing` tests.
- [ ] **Step 2:** Run on this host: `cargo test -p ringline provided` → the pure-math tests pass here even though arming is io_uring-only.
- [ ] **Step 3:** Implement `SizeClassRings` as a `Vec<ProvidedBufRing>`, one per class from config; register all at startup (`register_buf_ring` per bgid). Impl `RecvBufferProvider::arm` to pick the class via `class_index_for(&class_sizes, target_bytes)` and arm multishot against that class's bgid; `release` replenishes the owning class ring by bid.
- [ ] **Step 4:** hv01: `cargo build --release` + `cargo test -p ringline` (io_uring). Both-backend clippy. Expected: green.
- [ ] **Step 5: Commit** — `git commit -am "feat(recv/uring): size-class provided ring set"`

### Task 3.2: Feed the policy + re-arm on class change with hysteresis

**Files:**
- Modify: `ringline/src/backend/uring/event_loop.rs` (`handle_recv_multi`: after appending, `policy.observe(bytes)`; on `NeedAtLeast` from the parser path, `policy.hint(n)`; when `class_index_for(policy.target())` differs from the armed class at a message boundary, cancel + re-arm on the new bgid)

- [ ] **Step 1:** Add an io_uring-gated CQE-injection test (existing `test_dispatch_cqe` style in `event_loop.rs`) asserting: sustained large recvs drive a re-arm to a larger class; a single small recv does not (hysteresis).
- [ ] **Step 2:** hv01: run the test → FAIL first, then implement, then PASS.
- [ ] **Step 3:** Implement the observe/hint/re-arm wiring, re-arm only at message boundaries (accumulator empty or message fully consumed) to avoid splitting a message across class sizes mid-stream.
- [ ] **Step 4:** Both-backend clippy + hv01 test suite. Commit — `git commit -am "feat(recv/uring): adaptive class selection with hysteresis"`

---

## Phase 4: INC provider (io_uring ≥ 6.11 — validated on hv01, geometry from Phase 0)

### Task 4.1: Runtime INC probe + registration

**Files:**
- Modify: `ringline/src/backend/uring/ring.rs` (attempt `register_buf_ring_with_flags(.., IOU_PBUF_RING_INC)`; on `EINVAL` report unsupported)
- Create: `ringline/src/backend/uring/provided_inc.rs`
- Modify: `ringline/src/backend/uring/driver.rs` (choose INC vs size-class provider at startup from the probe)

- [ ] **Step 1:** hv01: assert the probe returns `Ok` on 6.12 and that a forced-classic path still works (feature/env toggle) so the fallback is exercised.
- [ ] **Step 2:** Implement `IncProvidedRing` (register with INC flag, single swept buffer size + depth from Phase 0). `RecvBufferProvider::arm` for `CopyOrConsume` arms multishot against the INC bgid; `Forward` domain must never be routed here (assert).
- [ ] **Step 3:** Both-backend clippy; hv01 build. Commit — `git commit -am "feat(recv/uring): INC provided-buffer provider + runtime probe"`

### Task 4.2: INC CQE handling (bid + offset) and incremental release

**Files:**
- Modify: `ringline/src/backend/uring/event_loop.rs` (`handle_recv_multi`: resolve INC completions to `RecvView` with `ReleaseToken::IncRegion`; map into the existing accumulator-append / in-place / sink paths preserving copy-counts; incremental replenish semantics replace per-bid replenish for this provider)

- [ ] **Step 1:** hv01 CQE-injection tests: a single large INC fill yields one append (not N); `with_data` in-place still fires for a whole-message fill; a partial fill across two CQEs stitches correctly. Write failing first.
- [ ] **Step 2:** Implement, following the `pending_recv_bufs`/`pending_replenish` interaction notes in the spec's Risks section. Confirm the zero-copy `with_data` in-place path and `set_recv_sink` still work under INC (both copy/consume out within a poll).
- [ ] **Step 3:** hv01 full suite + both-backend clippy. Commit — `git commit -am "feat(recv/uring): INC completion handling and incremental release"`

---

## Phase 5: mio adaptive shared scratch (host-testable)

### Task 5.1: Size the shared recv scratch from the aggregate signal

**Files:**
- Modify: `ringline/src/backend/mio/event_loop.rs` (replace the fixed `vec![0u8; 8192]` at `:131` with a scratch sized from a worker-level `SizingPolicy`; grow toward the aggregate high-water of observed read sizes / `NeedAtLeast`, shrink when quiet)

- [ ] **Step 1: Write the failing test** — mio-backend integration test: an echo server handling a large (256 KB) response records the number of `read()`+append cycles via a counter; assert it drops after the scratch grows (few cycles) versus the fixed-8 KB baseline (many).
- [ ] **Step 2: Run to verify failure** — `cargo test -p ringline --features force-mio <name>` → FAIL.
- [ ] **Step 3: Implement** — hold a `SizingPolicy` on the mio event loop; after each `handle_readable`, `observe(n)`; before reading, size the scratch to `policy.target()` (reallocate only on growth; the scratch is transient so no per-connection cost). Feed `NeedAtLeast` where the parse path surfaces it.
- [ ] **Step 4: Run to verify pass** — `cargo test -p ringline --features force-mio <name>` → PASS.
- [ ] **Step 5:** Both-backend clippy + `cargo test -p ringline`. Commit — `git commit -am "feat(recv/mio): adaptive shared recv scratch"`

---

## Phase 6: config surface + validation

### Task 6.1: Reinterpret config as override/cap; add opaque knobs

**Files:**
- Modify: `ringline/src/config.rs` (keep `recv_buffer(ring_size, buffer_size)` as an explicit override/cap; add opaque `inc_buffer_size`/`size_class_set` fields with swept defaults; validate consistency)

- [ ] **Step 1: Write failing config tests** — assert defaults enable adaptive mode; assert an explicit `recv_buffer(..)` override disables adaptation and pins geometry; assert invalid combinations are rejected on `build()` (mirror existing `config.rs` validation tests).
- [ ] **Step 2:** `cargo test -p ringline config` → FAIL.
- [ ] **Step 3:** Implement fields + validation + builder methods (opaque, `pub(crate)` fields per the API-design rule — no `pub` fields, no `Config` split). **Must** reserve the size-class bgid range `[recv_buffer.bgid, recv_buffer.bgid + NUM_SIZE_CLASSES)` and reject a `udp_recv_buffer.bgid` (or any registered bgid) that falls inside it — Phase 3.1 exposed this as an active `EEXIST`-at-launch footgun (the default UDP bgid was bumped 1→3 as a stopgap; validation must make custom configs safe too).
- [ ] **Step 4:** `cargo test -p ringline config` → PASS. Update committed `Cargo.lock` if deps changed (none expected). Commit — `git commit -am "feat(recv): config override/cap + opaque adaptive knobs"`

### Task 6.2: Copy-count invariant regression tests

**Files:**
- Create: `ringline/tests/recv_copy_counts.rs`

- [ ] **Step 1: Write the tests** — counter-instrumented parsers assert, per API: `with_data` in-place stays 0-copy and stays in-place on a message larger than the smallest class; `set_recv_sink` stays 1-copy-to-final; `with_bytes` value slices remain refcounted (no per-value alloc); `recv_forward` stays 0-copy (segment count only). Gate io_uring-specific assertions with `#[cfg(has_io_uring)]`.
- [ ] **Step 2:** Run on both backends (host mio + hv01 io_uring) → implement/adjust until PASS.
- [ ] **Step 3:** Commit — `git commit -am "test(recv): per-API copy-count invariant regression suite"`

### Task 6.3: Validation sweep — confirm the cliff flattens

**Files:**
- Use: `ringline/examples/ring_fill_bench.rs` (Phase 0)

- [ ] **Step 1:** hv01: re-run the concurrency sweep (conns 4→128, 256 KB) on the adaptive build; assert the 8→32 cliff flattens versus the pre-change baseline recorded in the review, and that small-response and mixed workloads do not regress. Capture RSS under 128 conns to confirm bounded memory.
- [ ] **Step 2:** Record the before/after numbers in `docs/recv-buffer-adaptive-design.md` (Validation section) and, if they establish a new baseline, in `BENCHMARKS.md` per repo convention. Commit — `git commit -am "docs: adaptive recv buffering validation results"`

---

## Self-review

**Spec coverage:** Problem/root-cause → Phase 0 harness + Phase 6.3 validation. Adaptive sizing → Phase 1. Buffer-domain type → Phase 2.1. Provider abstraction → Phase 2.2. INC path → Phase 4. Size-class path → Phase 3. mio scratch → Phase 5. Copy-count invariant → Phase 6.2. Config → Phase 6.1. TBD-by-sweep + INC de-risk → Phase 0 (gates 3–4). Public-typed-connections non-goal → not implemented (correct; deferred). All spec sections map to a task.

**Placeholder scan:** Pure/host-testable tasks (Phase 1, 2, 5, 6.1) carry complete real code and exact commands. io_uring provider tasks (Phases 3–4) intentionally reference the existing `ProvidedBufRing`/`ring.rs` patterns and the Phase-0-chosen geometry rather than fabricating unverifiable kernel CQE code — this is a deliberate honesty constraint (io_uring cannot compile on the dev host and INC internals depend on Phase 0), documented in "Environment & validation rules," not a placeholder omission. Each such task still specifies exact files, the test to write, and the verification host.

**Type consistency:** `SizingPolicy`/`SizingConfig`/`observe`/`hint`/`target`/`class_index_for` (Phase 1) are used consistently in Phases 3 and 5. `RecvDomain::{CopyOrConsume,Forward}`/`inc_eligible` (2.1) used in 3–4. `RecvBufferProvider::{arm,release}`/`RecvView`/`ReleaseToken` (2.2) used in 3–5. Consistent.
