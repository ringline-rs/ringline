# 2026-11: Audit of the file I/O paths

- **Status:** open — 10 findings (F1 to F10) and 4 performance findings (P1 to P4) recorded, F1 fixed (#859), F2 fixed (#861), F3 fixed (#862), F4 fixed (#863), F5 fixed (#864), F6 fixed (#870), F7 fixed (#871), F8 fixed (#872), F9 fixed (#873), F10 fixed (#874), P1 fixed (#875), P2 fixed (#876), P3 documented (#877), P4 documented (#878); 3 known issues (#824, #825, #845) confirmed, #824 since fixed (#854); 6 design limitations for the owner
- **Span:** 2026-11-10 · tree 6851de26 (`main`, 0.7.0-alpha.68) · reproduction branch `audit-fileio-repro` (e3397e64) on the fork

## Goal

Audit the code that opens, reads, writes, syncs, stats and closes files, on
both backends and all three subsystems (buffered `fs`, direct I/O, NVMe
passthrough), against a written list of invariants. No diff was under
review; the question was whether the code as it stands holds what its docs,
comments and tests say it holds, and what each operation costs. Five
questions: resource ownership (fds, table slots, buffers), the completion-key
and future-drop machinery, the mio pool path and result faithfulness, docs
against code, and performance.

Method (`cs:audit`): scope and invariants written first and agreed with the
owner, who added performance; a state map; five fresh read-only reviewer
agents, one per concern, in parallel; every finding re-checked by the auditor
by reading the quoted path, and run where the mio backend allows it on
macOS. The io_uring path cannot be compiled on the development host, so an
io_uring finding below is a trace unless its status names an anvil run.

Three issues on these paths were filed the same morning by another session
(#824, #825, #845, part of an io_uring-wide batch #824–#848). The reviewers
were given them as known findings to confirm and build on, and they are
listed below under "Known before the audit" rather than as new findings.

## Scope

Three file I/O subsystems, each a per-worker table of handles plus a slab of in-flight commands, sharing one completion-key space and one set of executor maps:

- fs (`ringline/src/fs.rs`): buffered files. `open`/`create` (OpenFuture), `read`/`write` (raw pointer, DiskIoFuture), `read_into`/`write_from` (owned `BytesMut`, ReadFuture/WriteFuture), `fsync`, `close` (synchronous), `stat` (StatFuture), `rename`, `remove`, `mkdir`. On by default (`ConfigBuilder::no_fs` turns it off).
- direct I/O (`ringline/src/direct_io.rs`, free functions in `ringline/src/runtime/io.rs` from line ~5090): `open_direct_io_file[_with]` (synchronous), `direct_io_read`/`write` (raw pointer), `direct_io_fsync`, `close_direct_io_file`. Opt-in via `ConfigBuilder::direct_io`.
- NVMe passthrough (`ringline/src/nvme.rs`, same free functions): `open_nvme_device`, `nvme_read`/`write`/`flush`, `close_nvme_device`. io_uring only (`IORING_OP_URING_CMD`, 128-byte SQEs). Opt-in via `ConfigBuilder::nvme`.

Code in scope:
- The `DriverCtx` methods in `ringline/src/handler.rs`: io_uring versions `open_nvme_device`/`nvme_*`/`close_nvme_device` (~1490-1760), `open_direct_io_file_with`/`direct_io_*`/`close_direct_io_file` (~1769-2050), `fs_open`/`fs_read`/`fs_write`/`fs_fsync`/`fs_close`/`fs_stat`/`fs_rename`/`fs_unlink`/`fs_mkdir` (~2050-2520), `disk_io_key` (~908); mio versions (`#[cfg(not(has_io_uring))]`, ~3201-3700) and `submit_disk_io`.
- io_uring completion handlers `handle_nvme_cmd`, `handle_direct_io`, `handle_fs` in `ringline/src/backend/uring/event_loop.rs` (~4276-4420); the ring helpers in `ringline/src/backend/uring/ring.rs` (`submit_openat`, `submit_direct_read`/`write`/`fsync`, statx/rename/unlink/mkdir, `submit_nvme_cmd`, `register_files_update`) and the SQE builders in `sqe.rs`; the fixed-file layout in `uring/driver.rs` (`nvme_fd_base`, `direct_io_fd_base`, `fs_fd_base` after connections and UDP sockets).
- mio: `ringline/src/disk_io_pool.rs` (the pool), the response drain in `ringline/src/backend/mio/event_loop.rs` (~605-650), `fs_fds`/`direct_io_fds` (`Vec<Option<Arc<OwnedFd>>>`) and `pending_fs_opens`/`disk_io_in_flight` in `mio/driver.rs`.
- Executor state in `ringline/src/runtime/mod.rs`: `disk_io_waiters`, `disk_io_results`, `disk_io_graveyard`, `fs_stat_results`, `abandoned_fs_opens`, the thread-local `DISK_IO_LIVE` (`disk_io_key_held`, `untrack_disk_io`), `wait_disk_io`, `take_disk_io_result`, `abandon_disk_io`, `wake_disk_io` (~490-520, 585-610, 920-980), and `impl Drop for Executor` (~652).
- `DiskIoFuture` in `runtime/io.rs` (~5024-5085); the futures and `release_orphans`, `park_buffer`, `park_or_drop`, `drop_buffer`, the `ORPHANED_*` thread-locals in `fs.rs` (~486-660, 800-1010).
- Exit: `Driver::run_shutdown` and `handle_shutdown_cqe` in `uring/driver.rs`, `worker.rs` ~1225-1260, the mio driver's drop.

Out of scope: the network paths, registered buffers (#841), SQE/CQE sizing (#837), `spawn_blocking`.

Tests that exist: `ringline/tests/fs.rs`, `direct_io.rs` (both backends), `disk_io_stale_results.rs` and `disk_io_teardown_buffers_uring.rs` (io_uring), `disk_io_graveyard_exit.rs` and `disk_io_teardown_buffers.rs` (mio), `fs_fd_ownership.rs` (Linux); unit tests in `mio/driver.rs` and `mio/event_loop.rs` (search `disk_io`, `fs_open`); `examples/nvme_smoke.rs`.

## Invariants

(I = inferred by the audit author; the rest from docs, CHANGELOG or CLAUDE.md)

1. Every file-table slot an open allocates is released exactly once: open failure, close, an abandoned open's completion, or worker exit (#551).
2. A stale handle (generation mismatch, or `closing`) is refused by every operation. Direct I/O and NVMe defer a close's slot release until `in_flight` is zero; fs releases at once and relies on the kernel's own file reference (#845).
3. Disk-I/O keys (Domain Invariant 3): no two held keys are equal; a result is stored only for a held key; a key is released when its future takes the result or is abandoned; a graveyard buffer is freed only by its completion.
4. Memory an in-flight operation references (caller buffer, `BytesMut`, statx box, path `CString`) stays valid until the completion is reaped, after a future drop and at worker exit (Domain Invariant 1; known broken by #824 and #825).
5. Every fd has one owner, a fixed-file slot or an `Arc<OwnedFd>`; every open is close-on-exec; no error path leaks an fd (submit failure, register failure, abandoned open, a pool result that reaches no worker) (#551, #546, #561).
6. A future dropped on a worker other than its owner touches no other worker's state and leaks only what it cannot safely release (#575).
7. A completion handler validates the CQE (slab `in_use`, key) before touching state and never panics on a stale or unexpected one.
8. Results are faithful: NVMe status words become errors, short reads and writes are counts not errors, `ReadFuture` never extends the buffer past what the kernel wrote.
9. (I) A failed submission releases its slab slot and key and returns an error, leaving nothing half-submitted; for disk I/O a full SQ is an error, not backpressure as it is for sends.
10. On mio: a close never closes an fd a queued pool operation holds; results carry owned fds; the pool exits when the request sender drops; a response arriving after its worker exited closes what it carries (#551, #546).
11. Docs state current behaviour: the fs module's io-wq claims (which operations use the bounded pool, its size, the 6.13 change, the measured table) and the future docs.
12. (I) Worker exit leaves no file open on either backend, apart from what in-flight operations hold.
13. (I, performance) An operation costs one SQE or one pool request, no blocking syscall on the worker thread, no allocation beyond what the API's ownership requires, and no per-operation scan proportional to table or slab size.

## Verdict per invariant

| # | Invariant | Verdict |
|---|---|---|
| 1 | slot released exactly once | broken by F2 (direct I/O and NVMe opens leak a slot on a bad path); every other exit releases once |
| 2 | stale handle refused; deferred release | broken by F3 after a generation wrap; weakened by F1 (fs releases at once and the kernel's file reference does not yet exist for an unsubmitted SQE) |
| 3 | completion keys | holds; `disk_io_stale_results.rs` pins it on io_uring |
| 4 | in-flight memory stays valid | broken by #824 and #825 (known); holds for the owned-buffer futures |
| 5 | one owner per fd, close-on-exec, no fd leak | holds |
| 6 | off-owner drop touches no other worker | holds; what it leaks is undocumented (F10) |
| 7 | handlers validate CQEs, never panic | partly: handlers check `in_use`, not the key, so a stale CQE on a reused slab index would be accepted; nothing produces one today, since a slot is released only by its own completion |
| 8 | results faithful | broken by F4 (`is_symlink` never true) and F7 (NVMe status word discarded) |
| 9 | failed submit leaves nothing half-submitted | holds for the release; the text "a full SQ is an error" is wrong (P3): a full SQ submits synchronously, and only an enter failure (`EINTR`, `EBUSY`, `EAGAIN`) reaches the caller |
| 10 | mio pool ownership | holds |
| 11 | docs state current behaviour | broken by F4, F5, F6, F7, F8, F9, F10 |
| 12 | exit leaves no file open | holds within #824's limit |
| 13 | per-operation cost | broken by F5 (no mio bound), P1, P2, P4 and the known #845 |

## Findings

Status words: **confirmed** means the auditor ran it (mio, this host) or the anvil run shows it; **traced** means read end to end on both sides but not run.

### F1 — io_uring: `fs::close` unregisters the fixed file before the loop submits the SQEs of the same poll (invariant 2). Traced; anvil confirmed: experiment `01a1c583-4481-714a-9765-e8998cd35b21`, the write completed `Err(EBADF)` and the file stayed empty.

**Fixed (#859):** `fs_close` defers while reads, writes or fsyncs are in flight, as below; the `fs::close` doc now says the slot is freed when the last of them completes. Test: `ringline/tests/fs_close_in_flight.rs`. The text below is as found at 6851de26.

`ringline/src/handler.rs:2301-2314`: `fs_close` runs `register_files_update(fd_index, &[-1])`, a synchronous `io_uring_register`, and releases the slot. The read, write and fsync SQEs pushed earlier in the same task poll are still in the user-space SQ (`push_sqe128` submits early only when the SQ is full) until the loop's `flush()` after `poll_ready_tasks`. The kernel resolves a fixed file when it issues the request, inside the `io_uring_enter` that submits it (from memory of the kernel source; the run below shows the `EBADF`, not the mechanism), so an fs operation issued before `close` in one poll finds an empty slot and completes with `-EBADF`; it succeeds only if the SQ happened to fill between the two calls. Direct I/O and NVMe defer the close while `in_flight > 0` and are not affected; on mio the same sequence lands in the file, pinned by `tests/fs_fd_ownership.rs::a_queued_write_lands_in_its_file_after_close`. This narrows #845's "Nothing breaks today because the kernel holds file references": the reference exists only for SQEs the kernel has seen. The `fs::close` doc is accurate ("on success the handle is invalid and its slot is free when this returns") and the backends differ.

Fix: the deferred close #845 proposes, in the shape of `close_direct_io_file`: a `closing` flag on `FsFileState`, refused by `validate_fs_file`, with `handle_fs` running the unregister and the release when `in_flight` reaches zero. `in_flight` is already maintained. Test: `a_write_issued_before_close_in_the_same_poll_lands` on the reproduction branch, both backends.

### F2 — a path with an interior NUL leaks a direct I/O or NVMe table slot, both backends (invariant 1). Confirmed (mio run; anvil run `01a1c583-4481-714a-9765-e8998cd35b21`, same output).

**Fixed (#861):** the three sites convert the path before allocating. Test: `ringline/tests/disk_open_bad_path.rs`. The text below is as found at 6851de26.

`handler.rs:1786-1795` (direct I/O, io_uring), `:1498-1506` (NVMe), `:3221-3232` (direct I/O, mio): `files.allocate()` runs before `CString::new(path)`, and the `?` on the conversion returns without `files.release(index)`. `fs_open` on both backends allocates first too, but releases the slot in an `inspect_err` on the conversion. Run with `max_files(2)`: three `open_direct_io_file("a\0b")` return `invalid file path`, `invalid file path`, `direct I/O file table full`, and a valid open afterwards fails with `direct I/O file table full` until the worker exits. Fix: convert the path before allocating, at the three sites. Test: `a_nul_path_does_not_leak_a_direct_io_slot` on the reproduction branch.

### F3 — the 16-bit generation wraps: a stale handle validates again after 65,536 releases of its slot and acts on the new occupant (invariant 2). Confirmed (mio run).

**Fixed (#862):** the generation is `u32` in the three tables and handles, so the wrap takes 2^32 releases (2^31 with deferred closes). Retiring a slot at `u32::MAX` was tried and dropped in review: it makes the table shrink under any long open/close loop (about 17 hours at 70k cycles/s with `max_files(1)`), a failure that no longer depends on a caller keeping a stale handle. Tests: `generation_does_not_repeat_after_65536_releases` in `fs.rs`, `direct_io.rs` and `nvme.rs`, and `ringline/tests/disk_handle_generation.rs`. The text below is as found at 6851de26.

`fs.rs:322-328`, `direct_io.rs:181-188`, `nvme.rs:291-298`: `release` does `generation.wrapping_add(1)` and the validators compare for equality. The free list is LIFO, so an open/close loop reuses one slot. Run (direct I/O, `max_files(1)`): a handle kept from the first open, 65,535 open/close cycles (0.90 s on mio in the saved run), a new open landing on slot 0 with generation 0 again; `close_direct_io_file(first)` returned `Ok` and closed the new file, and the new handle's own close then failed as invalid. Deferred direct I/O and NVMe closes bump twice, so 32,768 there. Nothing documents the limit. Fix: widen `generation` to `u32` in the three tables and handles (the handles are opaque, `Copy` and `!Send`; the size goes from 4 to 8 bytes), or document the wrap as a limitation. Test: the probe above, both backends.

### F4 — `Metadata::is_symlink` is never true: both backends stat through the link (invariants 8, 11). Confirmed (mio run; io_uring by the statx flags, anvil confirmed in the same run: `is_symlink=false is_file=true`).

**Fixed (#863):** `fs::symlink_metadata` stats without following (`lstat`; `AT_SYMLINK_NOFOLLOW`), `fs::stat` still follows and says so, and each `Metadata` field is documented. The ten `pub` fields stay. Test: `stat_follows_a_symlink_and_symlink_metadata_does_not` in `ringline/tests/fs.rs`. The text below is as found at 6851de26.

mio `fs_stat` (`handler.rs:3570-3595`) calls `libc::stat`, which follows symlinks; io_uring `submit_statx` (`sqe.rs:146`) passes `AT_STATX_SYNC_AS_STAT` without `AT_SYMLINK_NOFOLLOW`. Run: `stat(link)` gives `is_symlink=false is_file=true size=1`. The two `Metadata` conversions otherwise agree. No field of `Metadata` is documented (units of the times, that `mode` carries the type bits, which backend fills what), and the struct has ten `pub` fields against the repo's rule. Fix: either stat without following (`lstat`, `AT_SYMLINK_NOFOLLOW`) and say so, or drop `is_symlink`; document each field. Test: `stat_of_a_symlink_reports_is_symlink` on the reproduction branch.

### F5 — mio does not bound in-flight operations: `max_commands_in_flight` is never read, the pool is per worker while its docs say shared, and the threads share names (invariants 11, 13). Confirmed (mio run; code).

**Fixed (#864):** `submit_disk_io` counts each subsystem's operations from submission until the loop drains the response, and fails past its `max_commands_in_flight` with io_uring's text. The pool stays per worker; `ConfigBuilder::disk_io_threads` says so, and the threads are named `ringline-disk-io-<worker>-<thread>`. The `DiskIoPool` doc had already been corrected by #858. Test: `ringline/tests/disk_io_in_flight_bound.rs`. The text below is as found at 6851de26.

`backend/mio/driver.rs:523-541` builds the file tables from `max_files` only; `grep max_commands_in_flight ringline/src/backend/mio` finds one test config. `submit_disk_io` (`handler.rs:3160-3195`) checks nothing but the key and sends on an unbounded channel. Run: with `FsConfig::max_commands_in_flight(4)`, eight `read_into` calls issued before any await all succeed, where io_uring returns `filesystem command slab exhausted` at the limit. A handler that issues reads faster than the pool drains them grows the queue without bound (per queued operation a `Box<dyn FnOnce>`, a `DiskIoRequest`, an `Arc<OwnedFd>` hold and three map entries). `mio/event_loop.rs:100-116` creates a `DiskIoPool` in every `AsyncEventLoop::new`, so a runtime runs `workers × disk_io_threads` threads, all named `ringline-disk-io-0` or `-1`, while `disk_io_pool.rs:53-57` says "Created once during launch and shared (via `Arc`) across all workers" and `ConfigBuilder::disk_io_threads` does not say per worker (`docs/architecture.md:48-49` has it right). Fix: a per-worker counter from `max_commands_in_flight` that `submit_disk_io` fails past, decremented in the response drain, with io_uring's error text; and either one pool per runtime as the doc says or docs that say per worker and thread names that carry the worker index. Test: the eight-reads probe, mio.

### F6 — `disk_io_threads(0)` with fs or direct I/O configured passes validation; the documented error kind is wrong; a direct I/O open succeeds and its operations fail (invariant 11). Confirmed (mio run).

**Fixed (#870):** `build()` refuses the combination on mio, naming `no_fs()` (fs) or `direct_io` (direct I/O); the `disk_io_threads` docs say what 0 does on each backend. Test: `disk_io_threads_zero_with_fs_is_rejected_on_mio` in `config.rs`. The text below is as found at 6851de26.

`config.rs:386` says operations "return `Unsupported`" (`:1243` says only "0 = disabled"); `submit_disk_io` returns `io::Error::other("disk I/O pool not configured")`, kind `Other`. Run: `fs::open` fails with that error; `open_direct_io_file` (synchronous, no pool) returns `Ok` and the first read fails with the same message. `Config::validate` has no check. Fix: reject `disk_io_threads == 0` with `fs` or `direct_io` set on the mio build, or document the kind and the message.

### F7 — io_uring: the NVMe status word is discarded, and three public types describe a completion handler that does not exist (invariants 8, 11). Traced.

**Fixed (#871):** a failed command resolves to an `io::Error` whose inner error is `NvmeStatus`, the status word; `DirectIoCompletion`, `NvmeCompletion` and `DirectIoOp` are no longer public. Test: `a_status_word_reaches_the_caller_as_the_errors_inner_error` in `nvme.rs`, red when the word is mapped to `EIO`. The text below is as found at 6851de26.

`event_loop.rs:4303-4308` maps a positive `cqe->res` (the device status word, e.g. 0x281 media error) to `-EIO`; the caller cannot tell a media error from an invalid field, and no doc on `nvme_read`/`nvme_write`/`nvme_flush` says so. The only public text on the status word is `NvmeCompletion::is_success` (`nvme.rs:366-388`, exported from `lib.rs`), a type nothing constructs; `DirectIoCompletion` and `DirectIoOp` (`direct_io.rs:28`, `:256-285`) are public and likewise unused, and their docs ("Delivered to the ... completion handler") name a completion handler that has never existed in this repository: the types have been re-exported and unconstructed since the initial commit. Fix: carry the status word in the error (an `io::Error::other` wrapping it) or document `Err(EIO)`; remove the three types under the Unreleased breaking entries. Until then `is_success`'s comment is the only description of the status word.

### F8 — `OpenFlags::READ | OpenFlags::WRITE` is `WRITE` (invariant 11). Confirmed by the constants.

**Fixed (#872):** each flag and `open`'s `mode` are documented, the type doc says `READ | WRITE` is `WRITE` and names `READ_WRITE`, and a doctest pins it; `OpenFlags` is `PartialEq` and `Eq`. The text below is as found at 6851de26.

`fs.rs:143-152`: `READ = O_RDONLY` (0), `WRITE = O_WRONLY` (1), `READ_WRITE = O_RDWR` (2), with `BitOr`. A caller who writes `READ | WRITE` opens write-only and every read fails with `EBADF`. No constant is documented; `open`'s `mode` parameter is not either. No caller in the tree does this. Fix: document each constant and that `READ | WRITE` is `WRITE`; a doctest pins it.

### F9 — operations on one file are unordered on both backends, and `fs::fsync` reads as covering unresolved writes (invariant 11). Confirmed (reviewer's mio probe; io_uring by Domain Invariant 2).

**Fixed (#873):** the fs module doc says operations are independent, including on one file, that a write is in the file when its future resolves, and that `fsync` covers writes whose futures have resolved; `fsync`'s doc says the same. Whether fs should order them is L1. The text below is as found at 6851de26.

`disk_io_pool.rs:92-103`: N threads take requests from one channel with no per-file ordering. On io_uring the SQEs are independent (Domain Invariant 2). `fs::fsync` (`fs.rs:1000`) says "Fsync a file, flushing all data and metadata to disk"; `direct_io_fsync` says it correctly ("every write to `file` that completed before the call"). The reviewer's probe on mio with two pool threads: a 32 MiB `write_from` followed by `fsync`, both created before awaiting, resolved the fsync first in 19 of 20 runs; a later 4 KiB write to offset 0 lost to the earlier large write in 1 of 20 (4 of 20 on the record reviewer's rerun; one-run counts). Fix: a paragraph in the fs module doc (operations are independent; a write is in the file when its future resolves; `fsync` covers writes whose futures have resolved) and the sentence on `fsync`. Whether fs should offer ordering (linked SQEs, per-file serialisation) is L1.

### F10 — docs and comments false or missing at 6851de26 (invariant 11). Confirmed by quote and grep.

**Fixed (#874):** every item below is restated or added at HEAD, including the two kernel claims made from memory (the task-work read retry and `MAX_RW_COUNT`), which are unverified here; the io-wq table and the overlayfs/tmpfs and `dsync` claims stand as they were. The panic on a poll outside the ringline executor is on each future's doc. The full-SQ submit of P3 is documented in the fs, direct I/O and NVMe module docs (#877's documentation part). The text below is as found at 6851de26.

- `fs.rs:647-650`, `:677-680`; `runtime/io.rs:5170`, `:5202`, `:5233`, `:5311`: the `# Safety` sections say the buffer must stay valid "until the returned future completes"; a dropped future never completes and the operation runs on (#825). Until #825 lands, the contract to state is: until the operation completes, which a drop gives no way to observe, so after a drop the memory is leaked or the owned-buffer variants are used.
- Off-owner drops: `OpenFuture` (`fs.rs:478-481`, "closes the file and frees its slot"), `read_into`/`write_from` ("kept until the operation completes and then freed"), `DiskIoFuture`, `StatFuture`: dropped on a worker other than the owner, the slot, buffer or key is leaked for the worker's life, by design (#575); only the `Drop` comments say so. Polling on a thread that is no worker panics in `with_state` rather than staying pending. CHANGELOG's #551 entry carries the unqualified "The file is now closed and the slot freed".
- `DiskIoFuture`'s output is undocumented: bytes for reads and writes, `0` for fsync, rename, remove, mkdir, `direct_io_fsync` and every NVMe command.
- `NvmeUringCmd::read`/`write` (`nvme.rs:91`, `:122`) panic on `num_blocks == 0` with no `# Panics` section.
- `ConfigBuilder::nvme`/`direct_io`/`fs` (`config.rs:1195-1207`) restate the signature; what a reader needs is that each reserves `max_devices`/`max_files` fixed-file slots per worker on io_uring, and that `nvme(...)` on mio is accepted and every NVMe call fails.
- `runtime/io.rs:5083-5091`, `:5146-5155` and the direct I/O module doc describe io_uring only: the opens are a blocking `open(2)` plus a synchronous register (#845); on mio the open uses `F_NOCACHE` on macOS, where the module doc's alignment and `-EINVAL` claims do not apply; "Linux 5.6+" is below the 6.1 floor; the NVMe functions' "completes when the io_uring CQE arrives" is a pool result on mio, where they fail at submit.
- `fs.rs:1021-1027` (`fs::close`) says nothing about operations in flight on io_uring (F1, #845). `fs.rs:4` "File operations do not block the worker thread": `close` and the direct I/O and NVMe opens and closes do. `fs.rs:429` "asynchronously via io_uring": the pool on mio.
- `fs.rs:719-721`: the effective read length limit is `i32::MAX`, not `u32::MAX` (macOS rejects more with `EINVAL`; Linux caps at `0x7ffff000`, `MAX_RW_COUNT`, from memory of the kernel source); no truncation happens.
- A disk-I/O submit that finds the SQ full runs `io_uring_enter` inline (`engine/uring.rs:255-274`) and an `EINTR`, `EBUSY` or `EAGAIN` from it reaches the caller as the operation's error, with everything released; no entry point documents it (P3).
- `runtime/mod.rs:959`: `wake_disk_io` carries `#[cfg_attr(not(has_io_uring), allow(dead_code))]` and the mio drain calls it.
- Style: `fs.rs:714-715` argues for the design ("This avoids the use-after-free that motivates the `unsafe` on `read()`"); `direct_io.rs:5-7` compares instead of describing; `nvme.rs:17-19` documents three constants with one comment; `fs.rs:23-25` lists reads among the pool operations where a page-cache miss on ext4, XFS and btrfs retries from task work instead (kernel `io_rw_should_retry`, from memory of the source).
- Unverifiable here: the measured io-wq table in the fs module doc has no spec or run in the repository; the overlayfs/tmpfs `FMODE_NOWAIT` claims; the `dsync` FUA and flush claims.

### P1 — mio: about 7 µs per serial operation, 20× the `pread` floor, with three avoidable parts (invariant 13). Measured by the performance reviewer on this host (Apple M4 Max, release build, one worker, 4 KiB page-cache reads, N = 20,000, three runs in each of three processes; spread under 2% within a process except one run, 8.20 µs against 6.90 in the same process; 20% between processes).

**Fixed (#875):** a pool thread writes the wake pipe only when no pool thread has written it since the worker's last `drain_channels`, which clears the flag with a swap before reading the responses; the events `Vec` lives on the loop. Measured in a SystemsLab VM (experiment `01a1c8a1-2630-7115-cb4c-720b6c6df1b2`, `debian-13-6.12`, Linux 6.12.63, 16 vCPUs, `force-mio`; a probe of 4 KiB `fs::read_into` calls on a 4 MiB file with one worker and two pool threads, N = 20,000; the branch at e3e66544, before the clear became a load and a swap), five rounds interleaved with main and a second copy of main as the noise floor, three runs per variant per round: serial allocations per op 2.08 to 1.08 (the same to within 0.01 in all 15 runs per side); depth-64 median 1.21 µs (main) and 1.22 µs (main again) against 0.96 µs, fastest in 4 of 5 rounds, with round medians ranging 1.01 to 1.48 µs on main; serial, the control, 80.9 and 73.2 µs (main twice) against 70.4 µs, inside the floor. The wake-fd re-registration after every drain stays: kqueue needs it, and on epoll its cost was not measured. The text below is as found at 6851de26.

| mode | µs per op | allocations per op |
|---|---|---|
| `pread(2)` floor | 0.33 to 0.37 | |
| serial `read_into` | 6.9 to 8.4 | 2.07 |
| depth 64, 2 pool threads | 0.85 to 0.90 | 3.5 (includes `join_all`'s own) |
| depth 64, 1 thread / 4 threads | 0.76 to 0.77 / 1.15 | |
| serial `stat` | 7.9 to 9.7 | 3.07 |

The serial cost is the two thread hand-offs; the design accepts that. Avoidable: `mio/event_loop.rs:274-275` allocates a `Vec` of events on every loop iteration (one of the two allocations per serial read; the other is the required closure `Box`); `disk_io_pool.rs:100-102` writes the wake pipe once per completion with no coalescing on the writer (the reader coalesces); `mio/event_loop.rs:468-472` re-registers the wake fd after every drain, which kqueue needs and Linux's epoll does not. More pool threads made pipelined throughput worse (1 thread 0.76 to 0.77, 4 threads 1.15), so the worker side bounds it at this size; not profiled.

### P2 — io_uring: twelve hash operations, a `DriverCtx` of about thirty fields and a redundant waiter registration per operation, and a `Box<libc::statx>` per stat (invariant 13). By reading; cost estimated, not measured.

**Fixed (#876):** the executor keeps one map of `DiskIoEntry` (`Held { waiter, result, metadata }`, `Parked`, `AbandonedOpen`) with a multiply-and-fold hasher, and each step does one lookup in it plus the held-set update; the statx buffer is inline in `FsCmdEntry`. `make_ctx()` and the unused `in_flight` counter (#845) are unchanged. Measured in a SystemsLab VM (experiment `01a1c8b4-9cb0-716f-5ddc-c09347d05b8f`, `debian-13-6.12`, Linux 6.12.63, 16 vCPUs; the branch at a9c3f98f; a probe of 4 KiB `fs::read_into` calls on a 4 MiB file and `fs::stat` of it, one worker, N = 20,000; six rounds interleaved with main and a second copy of main, three runs each): io_uring `stat` allocations per op 2.01 to 1.01 in every run; io_uring depth-64 median 1.25 µs and 1.22 µs (main twice) against 1.03 µs, lowest in 5 of 6 rounds; mio depth-64 median 1.09 and 1.05 µs against 0.97 µs, lowest in 4 of 6 rounds; io_uring serial 49.2 and 49.3 µs against 48.8 µs; serial and stat otherwise inside the gap between the two copies of main. Depth-64 allocation medians were higher on the branch, by about 0.3 per op on io_uring and 0.15 on mio (counts that include `join_all`'s own; the per-run ranges overlap); serial allocations are unchanged, so the per-operation map code does not allocate. On the macOS workstation (mio) the same probe untraced gave 3.55 (main) and 4.03 (branch) depth-64 allocations per op over 12 runs each, and with a backtrace captured for every allocation, which slows the run, 2.607 and 2.602, one run each; the difference disappears when the run is slowed, which points to timing. Three further runs attributed it (the same VM image; main at ce617f46 against the branch at 0659a913; six rounds interleaved, three runs of 312 batches of 64 each per variant). Every `Poll::Pending` of a child of `join_all` registers the combinator's waker in `KEPT_WAKERS` (`runtime/waker.rs`) unless it is already there, and each wake of the task removes all of them, so each pending poll inserts one; the B-tree nodes and the two `Vec`s that `wake_kept_wakers` collects per wake are the allocations that differ by size class (464- and 560-byte blocks, 64- and 96-byte blocks, reallocations). The first run (experiment `01a1c948-9bd5-7132-5204-6821e5c1125d`) counted the outer task's polls: 2.075 against 1.826 allocations per op on io_uring, and at an equal count of polls above 6 the branch allocated more (144.9 against 126.9 per batch at 7), so outer polls do not explain it. The second (`01a1c94b-df8e-71f0-3d2e-1133b231da30`) counted each child's pending polls through a wrapper that boxed every child; the wrapper narrowed the io_uring difference to 2.872 against 2.834, so it is not used here. The third (`01a1c954-2c76-7189-125c-c1fc9a9f1fea`) counts them with an unboxed wrapper, and the difference is back: io_uring 2.146 against 1.759 per op, mio 3.265 against 3.173 (medians of 18 runs). Allocations per batch are a linear function of pending polls on both builds: per-run least-squares slope median 0.349 (branch) and 0.397 (main) on io_uring, 0.392 and 0.398 on mio. At an equal count of pending polls the branch allocates at most 2.0 more per batch than main on io_uring and 4.6 more on mio, and less in the higher bins (16-wide bins of pending polls per batch; io_uring, bins 64 to 160: 0.1 to 2.0 above main's 99 to 140, bins 176 to 320: 4.6 to 15.0 below; mio, bins 64 to 224: 0.3 below to 4.6 above main's 170 to 237, bins 240 to 384: 1.4 to 9.3 below; sparser bins differ in both directions). The branch has more pending polls per batch (median per run 173.7 against 102.7 on io_uring, 156.7 against 144.0 on mio), and the extra pending polls times the slope account for the difference: on io_uring 71 × 0.35 to 0.40 = 25 to 28 allocations per batch against 24.8 measured, on mio 12.7 × 0.39 = 5.0 against 5.9. `waker.rs` is identical in the two builds and every pending path of the fs futures calls `pending(cx)` once in both, so P2's code adds no allocation; the extra allocations are kept-waker allocations from extra pending polls. Why the branch has more pending polls is not measured: it was faster per op in the same run (depth-64 median 1.10 against 1.23 µs on io_uring, 1.10 against 1.21 on mio), and the inference is that its completions reach the task over more rounds with fewer completions each; the probe counts pending polls, not rounds. A pending poll of a combinator's child costs about 0.4 allocations in `KEPT_WAKERS` on main as on the branch; that is not part of P2. The text below is as found at 6851de26.

Per `fs::read_into`: one 128-byte SQE, one CQE, no syscall of its own, no allocation, no io-wq on a page-cache hit; and twelve SipHash operations over `disk_io_waiters`, `disk_io_results`, `disk_io_graveyard` and `DISK_IO_LIVE` (`wait_disk_io` runs at creation, `fs.rs:750`, and again on every pending poll, `fs.rs:854`), plus `make_ctx()` building a `DriverCtx` of about thirty fields (`uring/driver.rs:1240-1300`) and an `in_flight` increment and decrement nothing reads (#845). `fs::stat` allocates a `Box<libc::statx>` per call (`handler.rs:2330`); an inline `statx` in `FsCmdEntry` costs 256 bytes × `max_commands_in_flight`. Against a page-cache read the bookkeeping is a fraction of the cost; against NVMe passthrough at depth it is most of the worker's per-command CPU; neither is measured. The maps exist for stale-result rejection (#574), which a slot-indexed table with the 14-bit sequence as the slot's generation would give in O(1) (L3).

### P3 — io_uring: a full SQ submits synchronously inside the task poll (invariant 9's text). Traced.

**Documented (#877):** the fs module doc says a call that finds the submission queue full submits it inline (under SQPOLL, waits for the SQ thread) and returns the submit's error with nothing in flight; the direct I/O and NVMe module docs repeat the full-SQ submit and refer to it. The code is unchanged: the cost is one `io_uring_enter` on the worker when the queue is full; by reading, not user-visible at the defaults, and not measured. A retry of the error would cover `EINTR`, which a submit that does not wait does not return in practice (from memory of the kernel), or `EBUSY`, which needs completions reaped first, or `EAGAIN`, a resource failure a retry inside the poll would not clear. The text below is as found at 6851de26.

`engine/uring.rs:255-274`: `push_sqe128` on a full SQ calls `make_sq_room(1)`, one `io_uring_enter` on the worker, and errors only if the SQ is still full. The three slabs allow 768 disk SQEs against `sq_entries` 256. Not a user-visible cost at the defaults; it corrects invariant 9 and is the source of the undocumented errors in F10.

### P4 — io_uring: 16,384 keys per slab slot, with LIFO slot reuse (invariant 13). By reading; low.

**Documented (#878):** the `max_commands_in_flight` docs of `FsConfig`, `DirectIoConfig` and `NvmeConfig` state the limit and its trigger; the code is unchanged, and the slot-indexed table of L3 is what would remove it. The text below is as found at 6851de26.

A serial workload lands every operation on one slab slot; a future that completed but is never polled again and never dropped holds its key, and after 16,384 of them the next operation on that slot fails while 255 slots are free. The scan cost is benign (a held key costs one extra lookup per 16,384 allocations); the failure is the finding. The slot-indexed table of L3 removes the shared counter.

## Known before the audit

- #824: `run_shutdown` does not wait for the three command slabs; the driver
  is freed while the kernel may still use caller buffers and statx boxes
  (paths are probably copied at prep).
- #825: the raw-pointer APIs' safety contract ("until the returned future
  completes") cannot be met when the future is dropped; direct I/O and NVMe
  have no owned-buffer variant.
- #845: `open_direct_io_file`/`open_nvme_device` block the worker;
  the three closes are synchronous `FILES_UPDATE`s; direct I/O duplicates
  the fs path; `FsFileState::in_flight` is never read.

## Design limitations (questions for the owner, not fixes)

- L1 — Operations on one file are independent on both backends (Domain Invariant 2 on io_uring; N pool threads on one channel on mio). A caller orders them by awaiting. Should fs offer ordering (linked SQEs for a write-then-fsync pair, or per-file serialisation on mio), or is the documented contract enough (F9)?
- L2 — The mio pool costs two thread hand-offs per operation, about 7 µs serial on this host against 0.35 µs for the syscall (P1). The design accepts mio as correct rather than fast; the avoidable parts in P1 are the only cheap wins.
- L3 — The completion-key machinery is four hash maps keyed by a 32-bit key whose only purpose is stale-result rejection; a slot-indexed table per subsystem with the 14-bit sequence as the slot's generation gives the same property in O(1) and removes the 16,384-keys-per-slot limit (P2, P4). A refactor of `Executor`'s disk-I/O state and the five futures.
- L4 — One disk-I/O pool per worker (the code) or one per runtime (the docs)? Per worker isolates workers from each other's backlog and multiplies threads; per runtime is what `disk_io_pool.rs` describes and what `spawn_blocking`'s pool does (F5).
- L5 — The raw-pointer APIs (#825) and the fs/direct I/O duplication with blocking opens (#845) are known and filed; this audit adds F1, a consequence of the un-deferred `fs_close` that #845 does not state.
- L6 — The 16-bit generation (F3): widen, or document the wrap? Answered in #862: widened to `u32`.

## What the audit did not cover

- Nothing ran on io_uring except the reproduction run named below; every other io_uring statement is a trace. The NVMe path ran on no device.
- The kernel claims in the fs module doc: which filesystems give `FMODE_NOWAIT` (overlayfs, tmpfs), the io-wq pool-size formula, and the measured delay table (no spec or run in the repository); and `DirectIoOpenOptions::dsync`'s FUA and flush claims (`direct_io.rs:51-62`) under io_uring versus `pwrite`. Reviewers checked them against memory of the kernel source and said so.
- A profile of the mio worker under pipelined disk I/O (P1's depth-64 figures are measured; what bounds them is not).
- Registered buffers for direct I/O and NVMe (#841) beyond the reviewer's estimate; SQE/CQE sizing (#837).
- `fs::rename`, `remove`, `mkdir` and `stat` beyond their docs and error paths; the `Metadata` conversions were compared field by field but not run against unusual inodes (devices, sockets).
- The spawn, blocking and resolver pools, which share the "pool result reaches no worker" shape; only the disk pool was read.

## Reproductions

- F2, F3: the ownership reviewer's probe crate, rerun by the auditor on mio (`cargo test --test ownership`): `a_nul_path_leaks_the_direct_io_slot`, `a_stale_handle_validates_again_after_65536_releases`, both reproduce (65,535 cycles in 0.90 s in the saved run; 0.95 s on the auditor's rerun).
- F4, F6: the auditor's probe (`audit-probes/tests/docs.rs`): `stat(link)` reports `is_symlink=false is_file=true`; `fs::open` with `disk_io_threads(0)` fails with kind `Other`, "disk I/O pool not configured".
- F5: the auditor's probe (`audit-probes/tests/inflight.rs`): 8 of 8 `read_into` submitted with `max_commands_in_flight(4)`.
- F9: the mio reviewer's probe: fsync before its preceding 32 MiB write in 19 of 20 runs with two pool threads.
- P1: the performance reviewer's probe, figures in the table.
- F1, F2, F4 on io_uring: branch `audit-fileio-repro` on the fork (e3397e64), `ringline/tests/audit_fileio_repro.rs`, `experiments/audit-fileio-repro.toml`, anvil VM Debian 13, Linux 6.12: experiment `01a1c583-4481-714a-9765-e8998cd35b21`, io_uring build confirmed, `3 failed`: the write before `close` completed `Err(EBADF)` with the file empty; `is_symlink=false`; the direct I/O table full after three NUL paths.
