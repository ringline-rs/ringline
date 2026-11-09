# Kernel TLS (kTLS) — scoping

> **Since this was written:** #605 moved stream sends to `MSG_DONTWAIT` and a
> userspace wait for room, on every connection. Only `send_chain` sets
> `MSG_WAITALL`. Where this document says ringline sets `MSG_WAITALL` on every
> stream send, or that kTLS needs a second short-send strategy, there is now one
> strategy. Its cost is paid with or without kTLS, so N5 is no longer a cost of
> kTLS, and G2 asks whether the kTLS win holds with that cost in both arms. P-24
> has not been repeated. `tls_sw_sendmsg` and `tls_push_data`, which
> `tls_device_sendmsg` calls, allow `MSG_DONTWAIT`, in the source at Linux 6.1,
> 6.12 and 6.18. A `send_chain` part with `MSG_WAITALL` would still get
> `-EOPNOTSUPP`, so kTLS has to refuse `send_chain` or gather its parts into one
> queued send, as a TLS connection does today.

Note (2026-10-25): `ConnCtx::forward_to` was removed.

Note (2026-10-25): on io_uring a TLS receive writes ciphertext directly into
`CiphertextBuf`, so the `CiphertextBuf::append` copy under "Receive path" is
no longer made there.

Note (2026-10-25): the TCP provided-buffer ring was removed, with
`OpTag::RecvMulti` and the fallback receive.

**Status:** Scoping only. No code, no plan of tasks, no commitment. Every
premise below that the design rests on carries a verification record; the ones that could
not be verified are labelled, not smoothed over.
**Date:** 2026-09-05
**Related:** [`tls-unbuffered-design.md`](tls-unbuffered-design.md),
[`journal/2026-09-unbuffered-tls.md`](journal/2026-09-unbuffered-tls.md),
[`send-completion-design.md`](send-completion-design.md),
[`syscalls-and-copies.md`](syscalls-and-copies.md)
**Premise-check experiments (SystemsLab):**
`experiments/ktls-premise-probe.toml` — hv01 / `z2.baremetal`, experiment
`01a07046-b5fa-7182-77b8-d0800cb0c828`;
`experiments/ktls-uring-probe.toml` — hv01, `01a07047-d6c4-719f-645b-f9e926bcc2b0`
(superseded by G0; the in-tree revision has never been compiled — see its header);
**G0** — hv02 / `z1.baremetal`, `01a07207-0da5-714b-fcce-7e5bb5898f50` and
`01a0720b-b6ad-7169-1266-9ffa39288117`, both `success`

---

## Why this document is shaped the way it is

kTLS was the original request. It was deferred in favour of an unbuffered TLS
engine whose design doc claimed a 2 → 1 copy reduction. **That premise was
false**, and it survived twenty-five mutation checks, four adversarial
reviewers and two review gates per task, because every check pointed inward at
ringline while the false claim was about a *dependency*. It was caught only by
an allocation counter: 263,976 vs 264,000 bytes/op across the two engines.
See [`journal/2026-09-unbuffered-tls.md`](journal/2026-09-unbuffered-tls.md),
"Plan 4 — measurement".

So this document's organising rule is: **a premise is not usable until it has
been read in the primary source, and the document must say where.** Section
[Premise register](#premise-register) is the index; every claim in the body
carries a `[P-n]` tag pointing at it.

Two of the prior effort's own kTLS claims turn out to be **wrong**, and they
are the two that mattered most:

> **Correction 1 — "Software kTLS does not remove the remaining copy."**
> ([`tls-unbuffered-design.md:142`](tls-unbuffered-design.md), and the copy
> table at `:120`.) It removes **two of the three** memcpy-class passes on the
> send path, and on the fast path it hands the AEAD the caller's pages
> directly. The design doc's reasoning — "`sendmsg` copies plaintext into the
> kernel, which encrypts in place, the same count as userspace" — got the
> kernel half roughly right and the userspace half wrong, in the same way the
> falsified copy claim did. See [P-1], [P-2], [P-3].

> **Correction 2 — "Only NIC crypto offload (`TLS_HW`) reaches zero copies."**
> (`tls-unbuffered-design.md:121`, `:143`, `:598`.) `TLS_HW` does **not** reach
> zero copies on the ordinary `sendmsg` path: `tls_device.c` copies plaintext
> into skb frags exactly as `tls_sw.c` does, and the NIC encrypts during DMA.
> Zero requires `MSG_SPLICE_PAGES`, which is a `sendfile`/`vmsplice` path
> ringline does not have and cannot easily get (see
> [Question 4](#4-what-breaks)). `TLS_HW`'s win is **removing the CPU
> crypto**, not removing copies. See [P-6], [P-7].

Neither correction rescues the project: see
[Question 2](#2-is-tls_hw-reachable-on-hardware-we-own) and the
[recommendation](#recommendation).

> **G0 has since run, and its premise passed.** The gate this document defines
> below was executed on hv02 before the document shipped. Direct kernel
> tracing shows that **every** kTLS send in every mode — `send(2)`, io_uring
> `SEND` on a raw fd, on a **fixed** fd, and with `IOSQE_ASYNC` forcing io-wq
> — takes `sk_msg_zerocopy_from_iter`, and `sk_msg_memcopy_from_iter` was
> never called at all. [P-21]
>
> That converts this document's largest unverified premise into a measured
> one, and it is *stronger* evidence than the allocation counter G0 originally
> specified: it observes the kernel mechanism directly rather than inferring
> it from timing. **`[U-1]` is resolved; `[U-2]` is resolved as a hard "no",
> for a structural reason** [P-22].
>
> The decision does **not** change. G0 was only ever the cheapest way to
> falsify the effort early. What remains — G2, N2, N3, N4, and the now-measured
> N5 — is untouched by it, and `TLS_HW` remains unreachable [P-7], so software
> kTLS is the ceiling.

---

## GO/NO-GO criteria

Stated first, and deliberately falsifiable. The prior effort's criterion was
well-formed and the effort still failed it — that is the system working, and
the criteria below are written to fail the same way if the premises are wrong.

**G0 — premise gate. Runnable before a line of implementation code, and it
must be run first.** ✅ **RUN, 2026-09-05, on hv02. PASSED.** See
*[G0 as executed](#g0-as-executed)* immediately below for what was actually
measured and how it differs from — and improves on — the design below. The
original formulation is kept unchanged, because the substitution is the
interesting part.

Extend the microbenchmark harness that already exists on
the local `bench/tls-send-microbench` branch (the one that produced the
allocation counter) with a third arm: a real kTLS socket, keys installed by
hand, plaintext sent with `IORING_OP_SEND` **and no `MSG_WAITALL`** — kTLS
refuses it [P-19], so ringline's own `STREAM_SEND_FLAGS` cannot be used
verbatim. On hv01, at 1 KiB / 16 KiB / 64 KiB / 256 KiB / 1 MiB, report:

- **bytes allocated per operation inside the measured call**, the number that
  settled the last effort. Prediction from source: the kTLS arm allocates
  approximately **zero** in userspace, against ~264,000 for both rustls
  engines at 256 KiB. If the kTLS arm's allocation is comparable to the rustls
  arms, [P-1]/[P-2] are wrong and the effort stops here.
- **the cold-payload control.** Run the payload cold so each copy costs ~4.5×
  more (the journal's measured factor). Prediction: the kTLS arm's advantage
  **widens sharply**, because the copies it removes are real. If the gap does
  not move, no copy was removed — the exact discriminator that caught the last
  false premise.
- **`/proc/net/tls_stat`** before and after, to prove the traffic went through
  `TlsTxSw` and not through some fallback. [P-8]

#### G0 as executed

What ran was **not** the allocation counter and cold-payload control specified
above. It was better, and the swap is worth recording as method: instead of
*inferring* from userspace whether a copy happened, the probe **attached ftrace
kprobes to the kernel functions that decide it** —
`sk_msg_zerocopy_from_iter` (the pinned-pages path), `sk_msg_memcopy_from_iter`
(the copy path), `tls_sw_sendmsg`, `sock_sendmsg` and `io_send_zc` — and
counted calls and return values directly.

An allocation counter can only say "userspace allocated less". A kretprobe on
`sk_msg_zerocopy_from_iter` says *which kernel branch executed*, which is the
actual question. Where a cheaper direct observation of the mechanism exists,
prefer it to a proxy — the previous effort's proxy was a timing table, and it
took an allocation counter to overturn it.

Results (experiment `01a07207-0da5-714b-fcce-7e5bb5898f50`, hv02, Linux
6.12.74, 50 iterations per cell):

| mode | 4 KiB | 16 KiB | 64 KiB | 256 KiB |
|---|---:|---:|---:|---:|
| `send(2)` | 50 | 50 | 200 | 800 |
| io_uring `SEND`, raw fd | — | — | 200 | — |
| io_uring `SEND`, **fixed fd** | 50 | 50 | 200 | 800 |
| io_uring `SEND` + `IOSQE_ASYNC` | 50 | — | 200 | 800 |
| idle control | 0 | | | |

Those are `sk_msg_zerocopy_from_iter` call counts. Reading them:

- **Every count is exactly `iters × ceil(size / 16 KiB)`** — one call per TLS
  record, no more, no fewer, and summed `bytes` matches the payload exactly.
- **`sk_msg_memcopy_from_iter` produced no `COUNT` row in any arm**: the copy
  path was never entered.
- **Every kretprobe returned 0** (`g0zcr ... bytes=0`, i.e. the summed return
  value). A non-zero return is precisely what triggers
  `goto fallback_to_reg_send` (`tls_sw.c:1109`). It never fired.
- **The `IOSQE_ASYNC` arm is the one that matters most.** The doubt recorded in
  the original `[U-1]` was that `iov_iter_get_pages2` needs the submitting
  task's `mm`, and io-wq offload might run elsewhere. Forcing every send onto
  io-wq gave *identical* counts. io-wq workers are threads of the submitting
  process and share its `mm`; the doubt was unfounded, and is now closed by
  measurement rather than by argument.
- Accounting closes: `total_entries=8132 total_overrun=0`, so the trace buffer
  lost nothing. `/proc/net/tls_stat` moved `TlsTxSw 0 → 15` with
  `TlsTxDevice 0`, confirming the software path and not device offload.
- Every arm reported `rx_bytes` equal to `sent` with `rx_corrupt_reads=0` —
  so a plain `IORING_OP_SEND` on a kTLS **fixed** descriptor also round-trips
  correctly [P-23].

**GO** only if *all* of:

1. **G1 — copies.** ✅ **PASSED** (`01a07207-...`). Met by a stronger result
   than the criterion asked for: not "allocated ~0", but *the copy branch was
   never executed*, in every send mode including forced io-wq offload. [P-21]
2. **G2 — throughput.** A two-machine TLS benchmark on the rig (never
   co-located — this project withdrew `BENCHMARKS.md` in #205 over exactly
   that) shows the kTLS server beating the rustls server by a margin larger
   than the run-to-run spread, at ≥ 2 payload sizes. The bar is
   [`BENCHMARKS.md`](../BENCHMARKS.md)'s methodology, not its numbers.
3. **G3 — correctness envelope.** Interop against a rustls peer and an OpenSSL
   peer, both directions, including: a TLS 1.3 `key_update` from the peer, a
   `close_notify` from each side, a mid-stream `new_session_ticket`, and a peer
   that coalesces its final handshake flight with application data. A `close()`
   from inside a handler still sends `close_notify` (note the pre-existing
   io_uring bug at `runtime/io.rs` `ConnCtx::close()`, journal "Backlog" item 3
   — kTLS must not be built on top of it).
4. **G4 — fallback.** Every unsupported case (non-AES-GCM/ChaCha suite, kernel
   without `CONFIG_TLS`, `setsockopt` refusal, `TLS_HW` absent, rekey needed on
   a kernel < 6.14) silently and correctly falls back to the userspace engine,
   with a test per case.

**NO-GO** if any of:

- **N1** — ❌ **did not fire.** G0's replacement measurement (kernel kprobes on
  the branch itself) showed the pinned-pages path taken 100% of the time and
  the copy path never. *(This was the cheap early-falsification gate; the
  premise survived it.)* [P-21]
- **N2** — the rekey constraint [P-5] cannot be met on the target kernel and
  the fallback is "tear the connection down", **and** the deployment target is
  long-lived connections. At 2^24 records × 16 KiB = **256 GiB per direction**
  before AES-GCM's confidentiality limit forces a rekey [P-9], a saturated
  100 GbE connection hits it in ~22 s. On kernel 6.12 that is a forced close.
- **N3** — the RX conversion (`RecvMulti` → `RecvMsgMulti` on TCP, both
  backends) cannot be done without regressing the segmented-recv or
  direct-echo paths. [P-12] (Direct echo was removed in 0.7.0-alpha.5, and a
  plaintext TCP connection on io_uring no longer arms `RecvMulti`.)
- **N4** — the send-ordering hazard at the handshake→kTLS switch (see
  [Question 4](#4-what-breaks), "The switch is the sharp edge") has no clean
  answer within the per-connection send queue.
- **N5** — reinstating a per-connection short-send resubmit loop for kTLS
  connections (forced by [P-19]: kTLS refuses `MSG_WAITALL`) costs more than
  the copies kTLS removes. This is a regression against a shipped, argued
  decision ([`send-completion-design.md`](send-completion-design.md) §2), and
  it is **now quantified** [P-24]: under a 64 KiB `SO_SNDBUF` with a slow
  reader, **20 logical 256 KiB sends cost 74 SQEs — 54 of them short sends**,
  with `tls_sw_sendmsg` entered 127 times. That is the cost G2 has to absorb,
  and it lands on exactly the backpressured connections `MSG_WAITALL` was
  introduced to help. **This is now the leading NO-GO candidate**, because it
  is a measured cost on the same axis as the measured win.

**Explicitly not a GO criterion:** `TLS_HW`. It is unreachable on every host we
own [P-7] and cannot be a gate on work we could validate.

---

## Premise register

Every claim the design rests on, its verification status, and where to check it.
"Verified" means the primary source was opened and the cited lines read, or the
probe was run and its output is in the experiment log.

| # | Premise | Status | Source |
|---|---|---|---|
| P-1 | rustls' userspace encrypt costs **two** memcpy-class passes over the payload, on *both* engines | **Verified** | `rustls-0.23.41/src/common_state.rs` `write_fragments`; `src/crypto/ring/tls13.rs` `Tls13MessageEncrypter::encrypt`. Quoted in [`journal/2026-09-unbuffered-tls.md`](journal/2026-09-unbuffered-tls.md) "Evidence 2", and independently re-read here |
| P-2 | `tls_sw` **aliases** the plaintext scatterlist onto the ciphertext pages, so the ordinary kTLS send path is 1 copy + in-place AEAD | **Verified** | `net/tls/tls_sw.c:330-350` (`tls_clone_plaintext_msg`, `sk_msg_clone(sk, msg_pl, msg_en, skip, len)`), `:799` / `:806` (`sg_chain` of `sg_aead_in`→`msg_pl`, `sg_aead_out`→`msg_en`), `:1140` + `:1156` (the `tls_clone_plaintext_msg` call, then `sk_msg_memcopy_from_iter`), v6.12 |
| P-3 | `tls_sw` has a **faster** path that pins the caller's pages and never copies plaintext into the kernel at all | **Verified in source; not instrumented** | `net/tls/tls_sw.c:1103-1106` — `if (!is_kvec && (full_record \|\| eor) && !async_capable) sk_msg_zerocopy_from_iter(...)`; `net/core/skmsg.c:311-366` uses `iov_iter_get_pages2`. TX `async_capable` is zeroed by `kzalloc` (`tls_sw.c:2619`) and only ever set to 1 on an encryption *error* (`:829`) |
| P-4 | kTLS is all-or-nothing per connection | **Verified, and refined** | Both `dangerous_extract_secrets(self)` and its successor take `self`: `rustls-0.23.41/src/client/client_conn.rs:931`, `:944`; `src/server/server_conn.rs:961`, `:974`. **But** rustls ships a purpose-built kTLS API — see P-14 |
| P-5 | Linux **6.12 cannot rekey** a kTLS socket; 6.14 can, TLS 1.3 only | **Verified in source and measured on hv01** | v6.12 `net/tls/tls_main.c:636-638` — `/* Currently we don't support set crypto info more than one time */ ... return -EBUSY;`. v6.14 `net/tls/tls_main.c:639-653` adds the TLS 1.3 update path (absent in v6.13; present in v6.14-rc1). Probe on hv01: `second TLS_TX setsockopt -> Device or resource busy (errno 16)` |
| P-6 | `TLS_HW` (device offload) also copies plaintext into the kernel on the ordinary `sendmsg` path | **Verified** | `net/tls/tls_device.c:493-524` — `MSG_SPLICE_PAGES` branch does `iov_iter_extract_pages`; the `else if (copy)` branch does `tls_device_copy_data(...)`, which is `copy_from_iter` + `copy_from_iter_nocache` (`:393-416`) |
| P-7 | **No host we own supports `TLS_HW`** | **Verified in source and measured on hv01** | Only four in-tree `tlsdev_ops` implementations in v6.12: mlx5 (`en_accel/ktls.c:89`, TX+RX), Chelsio ch_ktls (`chcr_ktls.c:2132`, TX), Netronome nfp (`crypto/tls.c:465`, TX+RX), Fungible funeth (`funeth_ktls.c:126`, TX). Sweeping **every** `.c`/`.h` file in `drivers/net/ethernet/amazon/ena` (14 files), `intel/i40e` (38) and `intel/ice` (121) for `NETIF_F_HW_TLS`/`tlsdev_ops`/`tls_dev_add` yields **zero** hits. hv01 probe: **every** interface reports `tls-hw-tx-offload: off [fixed]` |
| P-8 | kTLS works end-to-end on hv01: ULP attach, key install, encrypt, decrypt | **Measured** | `experiments/ktls-premise-probe.toml`, hv01: kernel `6.12.90+deb13.1-amd64`, `CONFIG_TLS=m`, `CONFIG_TLS_DEVICE=y`, `CONFIG_TLS_TOE` not set. The C probe reported **8/8 PASS**. ⚠️ **The enclosing experiment `01a07046-b5fa-7182-77b8-d0800cb0c828` is recorded as `failure`**, because a *later, unrelated* step in the same job — the Rust io_uring probe — failed to compile (`E0499`, two `ring.completion()` borrows). Do not read the experiment's status as the probe's result; read the step's log. P-8 stands, this citation needed the correction |
| P-9 | AES-GCM's confidentiality limit is 2^24 records under rustls; ChaCha20-Poly1305 has none | **Verified** | `rustls-0.23.41/src/crypto/ring/tls13.rs:28` (`u64::MAX` for ChaCha20), `:48` / `:70` (`1 << 24` for AES-256-GCM / AES-128-GCM). rustls' `KernelConnection` explicitly does **not** track this: `src/conn/kernel.rs:37-52` |
| P-10 | A control record read with plain `recv()` fails with **EIO** | **Verified in source and measured** | `net/tls/tls_sw.c:1752-1772` — `tls_record_content_type` returns `-EIO` when the record is not `TLS_RECORD_TYPE_DATA` and `put_cmsg` failed or `MSG_CTRUNC` is set. hv01 probe: `PASS plain recv() of a control record fails with EIO` |
| P-11 | `IORING_OP_URING_CMD` / `SOCKET_URING_OP_SETSOCKOPT` accepts **any** level, so kTLS keys can be installed on a **fixed** descriptor | **Verified in source** | `io_uring/uring_cmd.c:313-329` (`io_uring_cmd_setsockopt`) has **no** level check, unlike `io_uring_cmd_getsockopt` at `:287-297` which is `SOL_SOCKET`-only. Exposed by the pinned `io-uring` 0.7.12 crate as `opcode::SetSockOpt`, whose `fd` is `impl sealed::UseFixed` (`opcode.rs:645-673`). `io_uring_cmd_sock` also requires `prot->ioctl` to be non-NULL (`uring_cmd.c:337-341`); the TLS ULP copies the base `tcp_prot` wholesale (`net/tls/tls_main.c:904`, `prot[TLS_BASE][TLS_BASE] = *base;`) and never overrides `.ioctl`, so it survives the ULP swap |
| P-12 | ringline's TLS recv path is a one-shot buffer-select recv (`RecvSelect`) on io_uring, plaintext TCP is a direct `Recv` into the accumulator, and mio uses `Read::read`; none can carry cmsgs | **Verified** | `arm_recv` (`backend/uring/event_loop.rs`) calls `Driver::submit_tcp_recv` (`backend/uring/driver.rs`), which submits `RecvSelect` for a TLS connection (`backend/uring/ring.rs`); plaintext: `Driver::arm_direct_recv_or_close` submits `Recv` through `Ring::submit_recv_direct` (`backend/uring/ring.rs`); mio `backend/mio/event_loop.rs:751` `handle_readable`, `stream.read` at `:789` and `:937`. The `RecvMsgMulti` TCP path that existed behind the default-off `timestamps` feature (handler `handle_recv_msg_multi_ts`) has been removed; see the CHANGELOG entry for the kernel receive-timestamp mode |
| P-13 | ringline has **no** `splice`/`sendfile` path in either direction | **Verified** | `grep -rn 'splice\|sendfile' ringline/src/` returns nothing. `ConnCtx::forward_to` is `opcode::Send` from a provided recv buffer (`backend/uring/ring.rs:340-355`); the file sink is `opcode::Write` (`:364`); NVMe is `IORING_OP_URING_CMD` into user memory (`ring.rs:912`) |
| P-14 | rustls has a **dedicated kTLS API** that survives the handover and handles key updates and session tickets | **Verified** | `rustls-0.23.41/src/conn/kernel.rs` (whole module); entry points `UnbufferedClientConnection::dangerous_into_kernel_connection` (`src/client/client_conn.rs:944`) and the server twin (`src/server/server_conn.rs:974`). `dangerous_extract_secrets` is **`#[deprecated]`** in favour of it (`client_conn.rs:929-931`) |
| P-15 | `enable_secret_extraction` is required, defaults to `false`, and ringline never sets it | **Verified** | Gate at `rustls-0.23.41/src/conn.rs:1198-1203`. `grep -rn enable_secret_extraction` over the ringline tree: zero hits. The `TlsConfig` and `TlsClientConfig` builders in `ringline-tls-config` build the rustls config, so a kTLS path can set it there; a config wrapped with `from_rustls` still needs the caller to set it |
| P-16 | TLS 1.3 RX decrypt-straight-into-the-caller's-buffer needs `TLS_RX_EXPECT_NO_PAD` | **Verified in source and measured** | `net/tls/tls_sw.c:2606-2612` — `zc_capable = tls_ctx->rx_no_pad \|\| version != TLS_1_3_VERSION`; used at `:2031-2033`. hv01 probe: `PASS TLS_RX_EXPECT_NO_PAD accepted` |
| P-17 | The kernel's cipher set covers everything rustls can hand it | **Verified** | Kernel: `net/tls/tls_main.c:102-111` (AES-GCM-128/256, AES-CCM-128, ChaCha20-Poly1305, SM4-GCM/CCM, ARIA-GCM-128/256). rustls: `ConnectionTrafficSecrets` has exactly three variants — `Aes128Gcm`, `Aes256Gcm`, `Chacha20Poly1305` (`src/suites.rs:218-242`). All three are supported by the kernel |
| P-18 | The unbuffered engine's rustls connection is in a **consumable owned position** | **Verified** | `TlsTable.conns: Vec<Option<TlsConn>>` (`tls/mod.rs:244`) → `TlsConn.conn: TlsConnKind` (`:224`) → `TlsConnKind::Unbuffered(UnbufferedConn)` (`:123`) → `UnbufferedConn.kind: UnbufferedKind` (`unbuffered/mod.rs:129`) → the rustls type. No `Rc`/`Arc`/pin/slab indirection. Only the *accessors* are `&mut`-only |
| P-19 | **kTLS rejects `MSG_WAITALL` outright.** `tls_sw_sendmsg` and `tls_device_sendmsg` fail any flag outside a small allow-list with `-EOPNOTSUPP`, and ringline sets `MSG_WAITALL` on every stream send | **Verified in source and measured on hv01** | v6.12 `net/tls/tls_sw.c:1231-1234` — allow-list is `{MSG_MORE, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_CMSG_COMPAT, MSG_SPLICE_PAGES, MSG_EOR, MSG_SENDPAGE_NOPOLICY}`; unchanged in v6.17 (`:1255-1258`). `tls_device.c:436-439` is narrower still. ringline: `STREAM_SEND_FLAGS = libc::MSG_WAITALL` (`ringline/src/completion.rs:1-10`), used by every stream send builder. Probe on hv01: `IORING_OP_SEND` with `MSG_WAITALL` on a kTLS fixed descriptor returned **-95 (`EOPNOTSUPP`)** |
| P-20 | kTLS keys can be installed on an io_uring **fixed** descriptor | **Measured on hv01** | Probe: `IORING_OP_URING_CMD/SOCKET_URING_OP_SETSOCKOPT set SOL_TCP/TCP_ULP="tls" on a FIXED descriptor (res=0)` and `SetSockOpt(SOL_TLS, TLS_TX, aes-128-gcm) accepted on a FIXED descriptor (res=0)`. Confirms P-11 end to end. Experiment `01a07047-d6c4-719f-645b-f9e926bcc2b0` |
| P-21 | **io_uring `SEND` on a kTLS socket takes the pinned-pages path, always — including on a fixed descriptor and under forced io-wq offload.** *(Was `[U-1]`, the document's largest unverified premise.)* | **MEASURED** | ftrace kprobes, experiment `01a07207-0da5-714b-fcce-7e5bb5898f50`, hv02, Linux 6.12.74. `sk_msg_zerocopy_from_iter` counts of exactly `iters × ceil(size / 16 KiB)` in every mode (`send(2)`, io_uring raw fd, io_uring **fixed** fd, io_uring + `IOSQE_ASYNC`); `sk_msg_memcopy_from_iter` **never called**; every kretprobe returned 0, so `goto fallback_to_reg_send` (`tls_sw.c:1109`) never fired; `total_overrun=0`; `/proc/net/tls_stat` `TlsTxSw 0→15`, `TlsTxDevice 0`. The `IOSQE_ASYNC` arm specifically retires the `mm`-context doubt |
| P-22 | **`SEND_ZC` / `SENDMSG_ZC` on a kTLS socket is structurally impossible, not merely unsupported.** *(Was `[U-2]`.)* | **Verified in source and measured** | `__tcp_set_ulp` clears the bit for *any* ULP: `net/ipv4/tcp_ulp.c:139-140`, `if (sk->sk_socket) clear_bit(SOCK_SUPPORT_ZC, &sk->sk_socket->flags);`. `io_send_zc` rejects on it at `io_uring/net.c:1377-1378`, **and so does `io_sendmsg_zc` at `:1445-1446`** — which is the one ringline actually uses for guards. Measured (`01a0720b-...`): kTLS `SEND_ZC` → `-95` with `io_send_zc` entered and `sock_sendmsg` never reached; a **plain-TCP control arm, same binary, same opcode, succeeded 3/3** with notification CQEs. Attributable, not inferred |
| P-23 | A plain `IORING_OP_SEND` (no flags) on a kTLS **fixed** descriptor round-trips correctly | **Measured** | `01a07207-...` and `01a0720b-...`: every arm reports `rx_bytes == sent` with `rx_corrupt_reads=0` (e.g. `uring-fixed size=65536 iters=20 sqes=20 sent=1310720 rx_bytes=1310720 short_sends=0`) |
| P-24 | The `MSG_WAITALL` loss [P-19] has a measured cost under backpressure | **Measured** | `01a0720b-...`, `mode=backpressure`: 64 KiB `SO_SNDBUF`, slow reader, 20 logical 256 KiB sends → `sqes=74 short_sends=54`, `tls_sw_sendmsg` entered 127 times, first CQEs `[131072, 16384, 98304, 16384]`. The pinned-pages path held throughout (320 calls, all returns 0), so this is purely resubmit overhead, not a copy regression |
| U-3 | The cost of a copy at 400/800 GbE | **UNVERIFIED, and out of reach** | Inherited verbatim from `tls-unbuffered-design.md:122-133`. The one number this project has is ~3.2 GiB/s/core on 200 GbE Graviton4. Do not extrapolate it into a core count |
| U-4 | Whether kTLS helps or hurts at ringline's *actual* payload sizes | **UNVERIFIED** | Every effect described here scales with payload. ringline's shipped benchmarks are dominated by 64 B–1 KiB ops, where per-syscall and per-record overhead dominate copies. G2 exists because of this |
| U-5 | Whether G0's result reproduces on the **6.12.90** target kernel | **UNVERIFIED — different host, different point release** | G0 ran on **hv02**, Linux **6.12.74**, because hv01 has been stuck `busy` with no scheduled job for ~8 h. hv01 is 6.12.90. Same series and the v6.12 source read throughout this document is identical for every function cited, so the result is expected to hold — but the exact-host cross-check has not been done, and "expected to hold" is this register's phrase for unverified. Rerun `experiments/` G0 on `z2.baremetal` when hv01 frees |
| U-6 | Toolchain floor for anything built through these jobs | **Noted, not a risk** | hv01 carries a pre-existing rustup at **1.85.0**; hv02 had none and rustup installed **1.97.1**. It is *not* the uniform 1.97.1 assumed earlier, so probe and harness code must compile on **1.85** to run on both hosts |

**`U-1` and `U-2` are absent from this table deliberately** — they were the
original unverified rows for the pinned-pages path and for `SEND_ZC`, and G0
resolved both. They are now **P-21** and **P-22**. References to `[U-1]`/`[U-2]`
elsewhere in this document are historical, and say so where they appear.

---

## 1. What software kTLS actually buys

**Short answer: on the send path, source says it removes two of the three
memcpy-class passes over the payload — considerably more than the prior design
doc claimed. On the receive path it removes one. Neither has been measured, and
G0/N1 exist to settle the send half before anything is built.**

### Counting convention

The last effort's confusion was partly a counting problem, so state it. Count
**memcpy-class passes over the payload**, from ringline's caller buffer to the
point the NIC can DMA it, *excluding* the one unavoidable AEAD read→write. A
pass is a `memcpy`/`copy_from_iter`/`copy_from_slice` of the bulk data. Where
the AEAD reads one buffer and writes another, that is the crypto pass, not an
extra copy.

`docs/syscalls-and-copies.md` uses a narrower convention (userspace only, the
kernel's own `sendmsg` copy not counted). Both are given below so neither can
be quoted out of context.

### Send path

| | userspace passes | kernel passes | total (this doc) | `syscalls-and-copies.md` convention |
|---|---|---|---|---|
| **ringline today** (buffered *or* unbuffered engine) | 2 | 1 | **3** | 2 |
| **kTLS_SW, ordinary path** [P-2] | 1 (pool slot) | 1 | **2** | 1 |
| **kTLS_SW, pinned-pages path** [P-3], **measured** [P-21] | 1 (pool slot) | 0 | **1** | 1 |
| **kTLS_HW** [P-6] | 1 (pool slot) | 1 | **2**, and no CPU crypto at all | 1 |
| kTLS + `MSG_SPLICE_PAGES` | 0 | 0 | **0** — but unreachable, see [Question 4](#4-what-breaks) | 0 |

Where each number comes from:

**ringline today = 3.** rustls 0.23.41 `WriteTraffic::encrypt` (and
`writer().write()` on the buffered engine, which reaches the same code) goes
`write_plaintext` → `CommonState::write_fragments`, which per fragment does
`let em = self.record_layer.encrypt_outgoing(m).encode();` then
`outgoing_tls[written..].copy_from_slice(&em)`. `Tls13MessageEncrypter::encrypt`
allocates a fresh `PrefixedPayload` per record, `extend_from_chunks` copies the
plaintext in (**pass 1**), seals in place, and the `copy_from_slice` above moves
the finished record into the pool slot (**pass 2**). `IORING_OP_SEND` then has
`tcp_sendmsg` copy the pool slot into skb pages (**pass 3**). [P-1]

**kTLS_SW ordinary = 2.** ringline still owns the SQE memory, so the caller's
bytes are copied into a `SendCopyPool` slot (**pass 1**) — Domain Invariant 1,
unchanged. Inside `tls_sw_sendmsg_locked`, `tls_alloc_encrypted_msg` allocates
the ciphertext pages, then `tls_clone_plaintext_msg` makes the *plaintext*
scatterlist reference **the same pages**, offset by `prepend_size`:

```c
/* net/tls/tls_sw.c:330-350 (v6.12) */
static int tls_clone_plaintext_msg(struct sock *sk, int required)
{
	...
	/* We add page references worth len bytes from encrypted sg
	 * at the end of plaintext sg. It is guaranteed that msg_en
	 * has enough required room (ensured by caller).
	 */
	len = required - msg_pl->sg.size;

	/* Skip initial bytes in msg_en's data to be able to use
	 * same offset of both plain and encrypted data.
	 */
	skip = prot->prepend_size + msg_pl->sg.size;

	return sk_msg_clone(sk, msg_pl, msg_en, skip, len);
}
```

`sk_msg_memcopy_from_iter` then copies the pool slot into those shared pages
(**pass 2**), and `tls_do_encryption` runs the AEAD with `sg_aead_in` chained to
`msg_pl` (`:799`) and `sg_aead_out` chained to `msg_en` (`:806`) — the same
pages — i.e. **in place**. That is one pass fewer than ringline pays today, and
it is the case the prior design doc described. It was right about this path and
wrong to think userspace matched it. [P-2]

**kTLS_SW pinned-pages = 1, and this is the interesting one.** Before it
reaches the copy path, `tls_sw_sendmsg_locked` tries:

```c
/* net/tls/tls_sw.c:1103-1106 (v6.12) */
if (!is_kvec && (full_record || eor) && !async_capable) {
	u32 first = msg_pl->sg.end;

	ret = sk_msg_zerocopy_from_iter(sk, &msg->msg_iter,
					msg_pl, try_to_copy);
```

`sk_msg_zerocopy_from_iter` (`net/core/skmsg.c:311-366`) calls
`iov_iter_get_pages2` and hangs the *caller's* pages off `msg_pl`. The AEAD
then reads those pages and writes the separately allocated `msg_en` pages — so
the plaintext is **never copied into the kernel**. The conditions are all
satisfied by an ordinary io_uring send:

- `is_kvec` is false — io_uring imports a user pointer, giving `ITER_UBUF`.
- `eor = !(msg_flags & MSG_MORE)` is true — ringline sets no `MSG_MORE`.
- `async_capable` for TX is zero out of `kzalloc` (`tls_sw.c:2619`) and is only
  ever set to 1 in the *error* arm of `tls_push_record` (`:829`). With a
  synchronous AEAD (AES-NI) it stays 0 for the life of the socket.

`num_zc` then forces `tls_encrypt_async_wait` before `sendmsg` returns
(`tls_sw.c:1206-1215`), so the pool slot is free the moment the CQE lands —
ringline's slot lifecycle is unaffected. Sub-conditions that fall back
gracefully to the 2-pass path: exceeding `MAX_MSG_FRAGS` scatter entries
(`= MAX_SKB_FRAGS`, `include/linux/skmsg.h:16`), and any `-EFAULT` from the
page pin (`goto fallback_to_reg_send` at `:1109`, label at `:1134`).

**This was the unverified step the design rested on, and it is now measured.** [P-21]
When this section was first written the source said the pinned-pages branch
*should* be taken, but nothing had confirmed io_uring actually lands there
rather than in the copy path — and io-wq offload plausibly runs in a different
`mm` context than the submitting task.

G0 settled it by attaching kprobes to the branch itself rather than inferring
from userspace. In every mode — `send(2)`, io_uring `SEND` on a raw fd, on a
**fixed** fd, and with `IOSQE_ASYNC` forcing io-wq —
`sk_msg_zerocopy_from_iter` was called exactly `iters × ceil(size / 16 KiB)`
times, `sk_msg_memcopy_from_iter` was **never called**, and every return was 0
so `goto fallback_to_reg_send` never fired. The `IOSQE_ASYNC` arm retires the
`mm` doubt directly: io-wq workers are threads of the submitting process and
share its address space, and forcing offload changed nothing.

**So the send-path count above is a measurement, not a prediction.** The
discipline that produced it is worth keeping: where a direct observation of the
mechanism is available and cheap, prefer it to a proxy. The previous effort's
proxy was a timing table, and it took an allocation counter to overturn it;
here a kretprobe answered the question outright.

### Receive path

Today, per received record: kernel DMA into a `ProvidedBufRing` buffer (0
passes) → `CiphertextBuf::append` copies the ciphertext into a contiguous
buffer, because `process_tls_records` needs one (**pass 1**) → rustls decrypts
into an owned `Vec` (`ReadTraffic::next_record`; the crypto pass) → that
plaintext is copied into the `RecvAccumulator` (**pass 2**).

Under kTLS RX: `tls_sw_recvmsg` with `darg.zc` decrypts **directly into the
caller's iovec** — i.e. straight into ringline's provided buffer — and
`CiphertextBuf` disappears entirely (**pass 1**: provided buffer →
`RecvAccumulator`, which the plaintext path already pays). `zc` requires
`TLS_RX_EXPECT_NO_PAD` on TLS 1.3 (`tls_sw.c:2606-2612`), which hv01 accepts
[P-16]. Without it, the kernel decrypts into skb pages and copies to the user
buffer — still 2 passes, i.e. no worse than today.

So RX is a 2 → 1 improvement, conditional on the `NO_PAD` promise. Note the
promise is exactly that. If the peer *does* pad, `tls_decrypt_sw`
(`tls_sw.c:1651-1658`) sets `darg->zc = false`, bumps `TLSRXNOPADVIOL` and
`TLSDECRYPTRETRY`, and **decrypts the record a second time**:

```c
/* net/tls/tls_sw.c:1651-1658 (v6.12) */
/* If opportunistic TLS 1.3 ZC failed retry without ZC */
if (unlikely(darg->zc && prot->version == TLS_1_3_VERSION &&
             darg->tail != TLS_RECORD_TYPE_DATA)) {
        darg->zc = false;
        ...
        return tls_decrypt_sw(sk, tls_ctx, msg, darg);
}
```

So the downside is 2× AEAD cost per padded record, not a correctness bug — but
it is a cliff a hostile peer can trigger at will by padding every record, and
`/proc/net/tls_stat`'s `TlsRxNoPadViolation` is the counter that would show it.
Whether to take the `NO_PAD` promise at all is a real security-adjacent
trade-off, not a free knob.

### The honest caveat

**The send-path count is measured [P-21]. The recv-path count is not.**

Send: G0 observed the kernel branch directly, in four send modes, with the
copy path never entered. That is as settled as this document can make it short
of running ringline itself.

Recv: everything in the previous subsection is still *structural, from source,
and unmeasured*. `darg.zc` was never traced; `TLS_RX_EXPECT_NO_PAD` was only
shown to be **accepted** [P-16], not shown to change the copy count. A recv-side
G0 — the same kprobe technique pointed at `tls_decrypt_sg` and the `darg.zc`
decision at `tls_sw.c:2031-2033` — is the obvious next cheap measurement, and
it has not been done. Do not quote the RX 2 → 1 improvement as a result.

And two things remain unmeasured on **both** paths, either of which can make
the whole win irrelevant:

- **[U-4] whether any of it matters at ringline's payload sizes.** Every effect
  here scales with payload; ringline's benchmarks are 64 B–1 KiB dominated.
  G2 exists for this.
- **[P-24] the measured `MSG_WAITALL` cost**, which pushes the *other* way and
  lands on exactly the backpressured connections that care most.

Also unmeasured, and possibly decisive [U-4]: **whether any of this matters at
ringline's payload sizes.** At 64 B–1 KiB, copies are not the cost; syscalls,
records, and per-CQE work are. kTLS adds no syscalls but does not remove any
either. It is entirely possible that kTLS is a clear win at 256 KiB and inside
noise at 1 KiB, which is where ringline's benchmarks live.

---

## 2. Is `TLS_HW` reachable on hardware we own

**No. Not on any host, on any rig, today. This is the headline.**

### What exists in-tree

Four drivers implement `tlsdev_ops` in Linux 6.12 [P-7]:

| Driver | Path | Direction | Hardware |
|---|---|---|---|
| mlx5 | `drivers/net/ethernet/mellanox/mlx5/core/en_accel/ktls.c:89` | TX + RX (RX capability-gated, `:127`) | NVIDIA/Mellanox ConnectX-6 Dx and later |
| Chelsio ch_ktls | `drivers/net/ethernet/chelsio/inline_crypto/ch_ktls/chcr_ktls.c:2132` | TX only | Chelsio T6 |
| Netronome nfp | `drivers/net/ethernet/netronome/nfp/crypto/tls.c:465` | TX + RX (`:591-596`) | Netronome Agilio |
| Fungible funeth | `drivers/net/ethernet/fungible/funeth/funeth_ktls.c:126` | TX only | Fungible DPU — vendor defunct |

The **Direction** column is from the kernel source cited. The **Hardware**
column is vendor knowledge, *not* verified from kernel source — treat the
specific part numbers as indicative. What is verified is that these four
drivers, and only these four, install `tlsdev_ops`.

(`drivers/net/ethernet/chelsio/inline_crypto/chtls/` is a different, older
mechanism — TLS_TOE, full TCP offload. hv01's kernel has `CONFIG_TLS_TOE` **not
set** [P-8], and the kernel community treats it as legacy.)

### What we have

| Rig | NIC | Driver | `TLS_HW`? |
|---|---|---|---|
| **hv01** (`z2.baremetal`, the kTLS-capable host) | Intel X710 ×3, Aquantia AQC 10G, Intel i350, Intel VFs | `i40e`, `atlantic`, `igb`, `iavf` | **No** — every interface reports `tls-hw-tx-offload: off [fixed]`, `tls-hw-rx-offload: off [fixed]`, `tls-hw-record: off [fixed]` |
| **hv02** (`z1.baremetal`) | X710 (same fabric, per `experiments/tcp-fanin-audit-ab.toml:14-18`) | `i40e` | **No** — all 38 `.c`/`.h` files of `drivers/net/ethernet/intel/i40e` in v6.12 contain zero `NETIF_F_HW_TLS`/`tlsdev_ops`/`tls_dev_add` references. *Not probed — inferred from the driver, not measured on the host* |
| **AWS** (`z1.g.small`, `z2.g.medium`, and the Graviton4 c8gn rigs) | ENA | `ena` | **No** — all 14 `.c`/`.h` files of `drivers/net/ethernet/amazon/ena` in v6.12 contain zero such references. *Not probed — inferred from the driver, not measured on the host* |

`[fixed]` in `ethtool -k` output means the driver does not implement the
feature at all — it is not a configuration that can be turned on. Measured, not
inferred: experiment `01a07046-b5fa-7182-77b8-d0800cb0c828`.

### What follows

1. **The zero-copy endpoint the prior design doc pointed at does not exist for
   us**, and would not exist even with the right NIC, because `TLS_HW` is not
   zero-copy either [P-6]. It is *zero-CPU-crypto*, which is a different and
   arguably larger win — but one we cannot measure, cannot regression-test, and
   cannot ship a claim about.
2. **`TLS_HW` cannot be a GO criterion, a milestone, or a motivation.** Any
   argument of the shape "kTLS is the delivery mechanism for NIC offload" is
   an argument about hardware nobody in this project can put a job on. Buying a
   ConnectX-6 Dx is the prerequisite for even scoping it.
3. **What is left is software kTLS**, which stands or falls entirely on
   [Question 1](#1-what-software-ktls-actually-buys) — and on G0.

---

## 3. What is the real scope

Costed honestly. "Small/Medium/Large" is relative to the unbuffered engine
(4 PRs, ~2,600 lines including tests), which is the only comparable in-tree
reference point.

### 3.1 Prerequisites ringline does not have

| # | Item | Size | Note |
|---|---|---|---|
| 1 | `enable_secret_extraction` on the rustls config | **Small** | It gates everything [P-15] and defaults false. The `ringline-tls-config` builders build the rustls config, so they can set it when kTLS is enabled. A config wrapped with `from_rustls` needs the caller to set it, and kTLS would silently stay off if the caller does not |
| 2 | By-value access to the rustls connection | **Small** | Two accessors: `TlsTable::take(conn_index) -> Option<TlsConn>` and `UnbufferedConn::into_kind(self)`. The ownership chain is already consumable [P-18] |
| 3 | TCP `RecvMsgMulti` on **both** backends | **Large** | See 3.3 |
| 4 | `setsockopt` on a fixed descriptor | **Small** | `opcode::SetSockOpt` exists in the pinned `io-uring` 0.7.12 and takes `impl UseFixed` [P-11]; the kernel imposes no level restriction on the setsockopt direction, and both `TCP_ULP` and `TLS_TX` were **measured** installing successfully on a fixed descriptor [P-20]. Note the `optval` (which holds **key material**) must satisfy Domain Invariant 1 — live until the CQE — and be zeroized after |
| 5 | A second short-send strategy | **Medium, and unbudgeted anywhere** | kTLS refuses `MSG_WAITALL` [P-19], so kTLS connections need the userspace partial-resubmit loop that `MSG_WAITALL` was landed to remove. Two strategies coexisting in `submit_next_queued`/`handle_send`, keyed on connection type |
| 6 | A cmsg helper | **Small** | The one cmsg parser, `backend/udp_gro.rs:21-52`, reads a single hardcoded option. Extract an iterator from it |

### 3.2 The unbuffered engine is genuinely the prerequisite — and better than we knew

The prior effort's *only* surviving justification for the unbuffered engine is
that `dangerous_extract_secrets` lives on `UnbufferedConnectionCommon`. The
conclusion holds; **the stated reason never did**, and that is worth recording,
because it was the sentence a merged feature rested on. That method is
implemented on the *buffered* types too — `ClientConnection` (`client_conn.rs:777`),
`ServerConnection` (`server_conn.rs:736`), `ConnectionCommon<Data>` (`conn.rs:472`)
and `Connection` (`conn.rs:125`) — so it never distinguished the two engines at
all. What does is the API that replaced it: **rustls 0.23.41 ships a
purpose-built kTLS API** [P-14] that the project's docs do not mention
anywhere, and it is unbuffered-only.

```
UnbufferedServerConnection::dangerous_into_kernel_connection(self)
    -> Result<(ExtractedSecrets, KernelConnection<ServerConnectionData>), Error>
```

`dangerous_extract_secrets` is **`#[deprecated]`** in favour of it, with the
reason spelled out in the attribute: *"does not support session tickets or key
updates"*. `KernelConnection` (`src/conn/kernel.rs`) survives the handover and
provides exactly two things:

- `update_tx_secret()` / `update_rx_secret()` → `(seq, ConnectionTrafficSecrets)`
  for a TLS 1.3 key update, with the sequence number reset to 0.
- `handle_new_session_ticket(payload)` (client only), so resumption still works.

**And nothing else — which decides the phasing of the whole effort.**
`KernelConnection` does no encryption and no decryption (`src/conn/kernel.rs`
module docs: "There are only two things that [`KernelConnection`] is able to
do"). Both the deprecated method and its replacement take `self`, so the
handover ends rustls' record layer in *both* directions at once. There is
therefore no "kernel TX, rustls RX" staging: **the RX conversion of §3.3 — the
one Large item — is on the critical path for any kTLS at all**, not a phase 2.
Any plan that proposes shipping TX first should be checked against this
paragraph.

Every ringline document that cites `dangerous_extract_secrets` as the kTLS hook
was out of date: `ringline/Cargo.toml:27`,
`ringline/src/tls/unbuffered/mod.rs:16`,
`tls-unbuffered-design.md:78`/`:592`/`:606`/`:609`,
`journal/2026-09-unbuffered-tls.md:41`/`:50`/`:449`, plus
`syscalls-and-copies.md:241` and `CHANGELOG.md`'s `Unreleased` entry, which
this list originally missed. (`CLAUDE.md:207` mentions kTLS but not the API, so
it needed no change.) ✅ **Corrected**, along with this section's own reasoning
above.

Note what the correction does *not* do: it does not make the engine's
justification any stronger than "rustls put the kTLS handover on the unbuffered
types". After #351 that is the whole case for the feature, and it is a claim
about rustls' API surface, not about ringline going faster.

The preconditions are strict and *shape the design*: the handshake must be
complete, `enable_secret_extraction` must be set, and **`sendable_tls` must be
empty** (`src/conn.rs:1209-1218`). Driving the unbuffered connection to
`WriteTraffic` satisfies the first and third naturally — rustls' own module
docs say so (`src/conn/kernel.rs:29-31`).

### 3.3 The RX conversion is the biggest single line item

kTLS control records (handshake, alert — including TLS 1.3 `key_update` and
`close_notify`) reach userspace only through a `TLS_GET_RECORD_TYPE` cmsg, and
a plain `recv()` that meets one **fails with `EIO`** [P-10] — verified in
source and measured. So the TCP recv path must become `recvmsg`-shaped.

What exists today is *not* infrastructure to build on:

- **TLS receives are a one-shot buffer-select recv** (`RecvSelect`) and
  plaintext receives are a direct `Recv` on io_uring; mio uses `Read::read`
  [P-12]. None can carry cmsgs.
- There is no TCP `recvmsg` path on either backend. The `timestamps`
  feature's `RecvMsgMulti` handler, since removed (see the CHANGELOG entry
  for the kernel receive-timestamp mode), never consulted `tls_table` and
  ignored segmented delivery, `direct_echo` and the zero-copy recv-buffer
  hold, so it was not a precedent to build on.
- A TCP `recvmsg` path must size its msghdr control buffer for TLS control
  records: `MSG_CTRUNC` on a control record is `EIO` [P-10].
- Two other io_uring TCP recv paths reach the accumulator and bypass the TLS
  dispatch entirely: `handle_recv_fallback` (`event_loop.rs:862`, appends at
  `:936`) and `flush_replenish_and_rearm` (`:729`). Both need the kTLS demux
  too.
- mio reads TCP through `std::io::Read::read`; its only `recvmsg` is for
  UDP. A kTLS mio backend needs a TCP `libc::recvmsg` path.

**Size: Large.** This is comparable to, or larger than, the whole unbuffered
engine, and it touches the recv hot path that segmented recv also wants to
change. N3 exists because of it.

### 3.4 Key updates and the confidentiality limit

This is the item most likely to be underestimated.

- **On kernel 6.12 — hv01, and therefore the only rig that can run this — the
  kernel refuses a second `TLS_TX`/`TLS_RX` with `EBUSY`** [P-5]. Source and
  measurement agree. TLS 1.3 `KeyUpdate` is therefore *unimplementable*; the
  only correct response is to tear the connection down.
- Rekey landed in **6.14** (absent in 6.13, present in v6.14-rc1), TLS 1.3
  only, same version and cipher required. So kTLS-with-rekey needs a kernel
  ringline cannot currently test on.
- rustls' `KernelConnection` **does not track the confidentiality limit** and
  says so explicitly (`src/conn/kernel.rs:37-52`): "It is the responsibility of
  the user of the API to track approximately how many messages have been sent."
  Under the userspace engines rustls does this for us. Under kTLS **ringline
  would have to count records**, per connection, per direction, and act at the
  limit.
- The limit for AES-GCM is **2^24 records** [P-9] — 256 GiB per direction at
  16 KiB records. Not academic for a runtime designed against 800 GbE.
  ChaCha20-Poly1305 has no practical limit (`u64::MAX`) but gives up AES-NI and
  rules out mlx5 offload; picking it to dodge the problem is a real option and
  a real trade.
- The peer can also *send* a `KeyUpdate` at any time. Detecting it requires the
  cmsg path (3.3), parsing the handshake record, and calling
  `update_rx_secret()` + a fresh `TLS_RX` setsockopt — again impossible on 6.12.

**Size: Medium on 6.14+, and a hard blocker on 6.12.** N2.

### 3.5 The two-backend split

- **io_uring:** the target. Everything above applies.
- **mio on Linux** (`force-mio`): kTLS would technically work — it is a socket
  feature, not an io_uring feature — but needs a `recvmsg` path built from
  scratch (3.3) and gains less, because mio's TLS sends already degrade to
  copies. `CLAUDE.md`'s stance is that mio must be *correct and
  non-pathological, not optimal*. **Recommendation: do not implement kTLS on
  mio.** Let mio always take the userspace engine, and make that an explicit
  documented asymmetry rather than an accident.
- **mio on macOS:** kTLS does not exist. Not applicable.

That asymmetry has a real cost, and it is the same one the unbuffered engine
paid: **the maintainer's dev machine cannot type-check, lint, or test the kTLS
path at all.** `lib.rs` applies `#[cfg_attr(not(has_io_uring), allow(dead_code))]`
to the whole `tls` module, so even dead-code lints are invisible on macOS
(journal, "Dead-code lints are invisible on macOS"). Every check would be
hv01/CI-only. Budget for that; the unbuffered effort lost a red branch to it
three separate times.

### 3.6 `ConnCtx` API surface

Smaller than expected. `ConnCtx`'s TLS-aware surface is `tls_info()`
(`runtime/io.rs:1599`), `eof_truncated()` (`:1617`), `connect_tls*`
(`:1629`, `:1646`), and `close()` (`:1689`); the rest is TLS-aware only
transitively through `DriverCtx::send`.

Under kTLS:

- `tls_info()` must still work. `KernelConnection` exposes
  `negotiated_cipher_suite()` and `protocol_version()`, so those survive; ALPN
  does **not** — it lives on the consumed `CommonState` — and SNI is
  ringline's own field (`UnbufferedConn::sni`). **Both must be snapshotted
  into a `TlsInfo` before the handover.**
- `eof_truncated()` must keep distinguishing a peer `close_notify` from a bare
  FIN. Under kTLS that signal arrives as a control record via cmsg, not from
  rustls. New plumbing, same contract.
- `send_parts().guard()`: today it is **not refused** under TLS — it silently
  copies the guard's bytes and drops the guard (`handler.rs:2893-2924`,
  contradicting `CLAUDE.md:243`). Under kTLS a guard could genuinely stay
  zero-copy, since the kernel takes plaintext.

  **The route is now known, and it is not the obvious one.** `SendMsgZc` — what
  ringline uses for guards today — is *structurally unavailable* on a kTLS
  socket: attaching any ULP clears `SOCK_SUPPORT_ZC`, and `io_sendmsg_zc`
  refuses on that bit [P-22]. But it is also unnecessary, because ordinary
  `IORING_OP_SEND` already pins the caller's pages [P-21]. So a guarded send
  under kTLS is a **plain `Send` from the guard's memory, with the guard held
  until the CQE** — the same lifetime rule Domain Invariant 1 already states,
  minus the ZC notification CQE.

  That makes it the most attractive downstream item here, and it is the one
  place kTLS reaches **zero** userspace passes: no `SendCopyPool` slot, no
  kernel copy. Note it also means the send path would carry *three* shapes
  (pool-slot copy, guard-with-notification for plaintext, guard-without for
  kTLS), which is scope, not a freebie.
- **`send_chain` encrypts in userspace on a TLS connection.** The builder
  gathers the parts, and `SendChainBuilder::finish_tls` encrypts them and
  queues the records; `finish_tls` encrypts through `encrypt_tls_send`, the
  function `send` uses. Under kTLS the chain must send the plaintext:
  ciphertext written to a kTLS socket is encrypted again by the kernel.

**No new public config surface is proposed.** Following the unbuffered
engine's precedent: a default-off cargo feature, decided later.

### 3.7 Headline scope estimate

| Cluster | Size | Why |
|---|---|---|
| TCP `RecvMsgMulti` conversion, both backends | **Large** | 3.3. Touches the recv hot path, has no precedent in the tree, and mio needs a `recvmsg` path written from nothing |
| Second short-send strategy | **Medium** | 3.1 item 5 / [P-19]. Undoes a shipped decision and adds a per-connection branch to the send path |
| Handshake → kTLS switch (ordering + drain preconditions) | **Medium** | [Question 4](#4-what-breaks). Small in lines, large in ways to get silently wrong — the class of bug the unbuffered engine hit three times |
| Key updates + confidentiality-limit accounting | **Medium on 6.14+, blocked on 6.12** | 3.4 / [P-5] / [P-9] |
| Control-record demux (`close_notify`, alerts, `key_update`) + `eof_truncated` plumbing | **Medium** | 3.3, 3.6 |
| Engine selection, fallbacks, prerequisites 1/2/4/6 | **Small** | 3.1 |

**Total: comparable to or larger than the unbuffered engine** (4 PRs,
~2,600 lines), on a path where **the maintainer's dev machine can neither
compile nor lint the code**, and where the only available rig **cannot exercise
the key-update half of the correctness envelope**.

**The single biggest risk has changed since first draft, and it is worth
recording why.** It was `[U-1]` — that the whole effort rested on an unmeasured
claim about what the kernel does with an io_uring send, the same shape of
mistake that had just cost four PRs. G0 retired that for the price of one
probe [P-21].

**What replaced it is N5 [P-24].** kTLS refuses `MSG_WAITALL`, and under
backpressure that measured at 74 SQEs and 54 short sends for 20 logical
256 KiB sends. So the effort now has a **measured win on data movement and a
measured loss on syscall count, on the same connections**, and no measurement
of which dominates at the payload sizes ringline actually serves [U-4]. That is
a genuinely undecided cost/benefit question rather than an unexamined premise —
a better place to be, but not a resolved one, and it is exactly what G2 exists
to settle.

---

## 4. What breaks

Checked against `CLAUDE.md`'s *Domain Invariants* and
[`send-completion-design.md`](send-completion-design.md).

| Invariant | Under kTLS |
|---|---|
| **1. SQE memory outlives the operation** | **Survives, with a new instance.** Pool slots still hold the data until the CQE. But `SetSockOpt`'s `optval` is *key material* referenced by an SQE — it must live until the CQE and be zeroized after. The obvious mistake (a stack temporary) is a use-after-free with secrets in it. Treat the crypto-info block as a first-class pinned allocation |
| **2. io_uring does not order independent SQEs** | **Needs rethinking at exactly one point: the switch.** See below |
| **3. Stale CQEs are normal** | **Survives, extended.** The `SetSockOpt` CQE needs generation validation like any other, and the recv re-arm across the switch will produce in-flight `RecvMulti` CQEs for a connection that is now `RecvMsgMulti` |
| **4. No CQE-skip for pool-backed sends** | **Survives unchanged** |
| **5. Short sends happen** | **BROKEN — this is the sharpest finding in the document.** kTLS refuses `MSG_WAITALL` with `-EOPNOTSUPP` [P-19], measured, and ringline sets it on every stream send. See below |
| **6. `ENOBUFS` on multishot recv** | **Survives**, but the re-arm path must be written for `RecvMsgMulti`, which ringline does not have on TCP |
| **7. `EINTR`/`EBUSY` on submit is backpressure** | **New hazard.** `EBUSY` from `SOCKET_URING_OP_SETSOCKOPT` is *not* backpressure — it is the rekey refusal [P-5]. Retrying it forever is a hang. The two must not be conflated |

### `MSG_WAITALL` is refused, and that undoes a shipped decision

`tls_sw_sendmsg` rejects any `msg_flags` outside a small allow-list:

```c
/* net/tls/tls_sw.c:1231-1234 (v6.12; identical at v6.17:1255-1258) */
if (msg->msg_flags & ~(MSG_MORE | MSG_DONTWAIT | MSG_NOSIGNAL |
                       MSG_CMSG_COMPAT | MSG_SPLICE_PAGES | MSG_EOR |
                       MSG_SENDPAGE_NOPOLICY))
        return -EOPNOTSUPP;
```

`MSG_WAITALL` is not in it. `tls_device_sendmsg` (`tls_device.c:436-439`) is
narrower still. ringline's `STREAM_SEND_FLAGS` **is** `MSG_WAITALL`
(`ringline/src/completion.rs:1-10`), set by every stream send builder — so
**every ringline send on a kTLS socket fails immediately with `EOPNOTSUPP`**.
Measured on hv01, not inferred: the io_uring probe's `IORING_OP_SEND` returned
`-95`.

This is not a small compatibility fix. `MSG_WAITALL` on stream sends is a
deliberate, argued, shipped decision —
[`send-completion-design.md`](send-completion-design.md) §2 landed it precisely
to collapse the CQE → userspace-resubmit → CQE round trips that short sends
otherwise cost, and `CLAUDE.md`'s Domain Invariant 5 records it as the
mechanism. Under kTLS, ringline must:

- drop `MSG_WAITALL` for kTLS connections, and
- reinstate the userspace partial-resubmit loop **for those connections only**,
  so the send path carries two short-send strategies keyed on connection type,
  and
- keep the resubmit ordered — a partial kTLS send leaves a *partial TLS record
  open* in the kernel (`pending_open_record_frags`), so anything that
  interleaves on that socket corrupts the record stream. Invariant 2's
  per-connection send queue already guarantees this, but the coupling is new
  and now relied on.

It also interacts with the coalescing interlock the unbuffered effort found by
accident (journal, "an accidental interlock"): `submit_next_queued` coalesces
consecutive pool-backed sends into one `SendMsgCoalesced` without inspecting
`OpTag`, and under kTLS a coalesced send is *one TLS record*, which changes
what a "logical send" means on the wire.

**The cost is now measured, and it is not small** [P-24]. Under a 64 KiB
`SO_SNDBUF` with a deliberately slow reader (experiment
`01a0720b-b6ad-7169-1266-9ffa39288117`, `mode=backpressure`), **20 logical
256 KiB sends cost 74 SQEs, 54 of them short sends**, with `tls_sw_sendmsg`
entered 127 times and first CQEs of `[131072, 16384, 98304, 16384]`. The
pinned-pages path held throughout (320 calls, all returns 0), so this is pure
resubmit overhead — not a copy regression, and not something the copy win
offsets automatically.

Read the two measured results together: **G0 measured a win on data movement,
and this measured a loss on syscall count, on the same connections.** They are
not on the same axis and cannot be netted by argument. G2 is where they meet,
and N5 is the criterion that decides it.

**This should be near the top of any implementation estimate.** It was not
anticipated by any prior document, and it was found by running a probe rather
than by reading — which is the argument for running G0 before designing
anything, and which is also how the win was found.

### The switch is the sharp edge

Two orderings must hold, and neither is expressible in the current machinery.

**TX.** `dangerous_into_kernel_connection` requires `sendable_tls` empty, but
that is a rustls-side condition — it says nothing about ringline's own
per-connection send queue, which may still hold un-submitted handshake-record
SQEs. If `TLS_TX` is installed while those are queued, the kernel begins
encrypting from `ExtractedSecrets.tx` sequence number *N* while records
0..*N* are still on ringline's queue. Application data would reach the wire
ahead of the handshake tail: `bad_record_mac` at the peer, which is the exact
failure mode invariant 2 exists to prevent, and the exact failure mode the
unbuffered engine hit twice.

Two candidate answers, both needing design work: `IO_LINK` the `SetSockOpt`
behind the last handshake `Send` (cheap, but `IO_LINK` semantics under
`MSG_WAITALL` short sends need checking), or make the switch a queue element so
`submit_next_queued` drains past it in order (invasive, but it is where the
ordering guarantee already lives).

**RX.** `TLS_RX` installs a key at `ExtractedSecrets.rx` sequence *M*, meaning
"the next record on the wire is record *M*". That is only true if
`CiphertextBuf` is **empty** at the moment of the switch. If the peer coalesced
application data — or a `close_notify` — with its final handshake flight, those
bytes are already in ringline's buffer, and rustls is about to be consumed.
They cannot be handed to the kernel. So the switch must be conditional on
`CiphertextBuf` being drained; if it is not, either delay a round or decline
kTLS for that connection. This is a *checkable precondition*, and it should be
an assertion with a fallback, not a comment.

Note this is precisely the case the buffered engine gets wrong today (journal
"Backlog" item 7: `feed_tls_recv` returns `HandshakeJustCompleted` before the
`peer_has_closed()` check). kTLS would turn a latent bug into a data-loss bug.

### `sendfile` / NVMe-to-socket does not compose

The prior design doc listed it as a downstream benefit *"needs its own
investigation"*. Investigated:

1. **ringline has no splice/sendfile path at all** [P-13].
   `grep -rn 'splice\|sendfile' ringline/src/` returns nothing.
   `ConnCtx::forward_to` — the closest thing — is `opcode::Send` from a
   *provided recv buffer* (`backend/uring/ring.rs:340-355`), i.e. already
   user-memory-to-socket. There is no kernel-to-kernel path to preserve.
2. **NVMe passthrough reads into user memory** (`ring.rs:912`,
   `IORING_OP_URING_CMD`), so there is no page-cache page to splice.
3. `MSG_SPLICE_PAGES` — the flag both `tls_sw.c:1088` and `tls_device.c:493`
   honour for a genuine zero-copy send — is not settable from
   `IORING_OP_SEND`; it is what `sendfile`/`vmsplice` set internally.

**Conclusion: strike it.** It is not a kTLS benefit for ringline. It would be a
benefit for a *different* ringline that had a splice-based forward path, and
building that is a separate project with its own justification.

---

## Unverified, listed explicitly

**Resolved since first draft** — kept here so the record shows what changed and
why, not silently deleted:

- **`[U-1]` → [P-21], MEASURED.** Whether io_uring's `IORING_OP_SEND` reaches
  `sk_msg_zerocopy_from_iter`. Yes, in every mode, including on a fixed
  descriptor and with `IOSQE_ASYNC` forcing io-wq — which is what retired the
  `mm`-context doubt. `sk_msg_memcopy_from_iter` was never called.
- **`[U-2]` → [P-22], resolved as a hard NO.** `SEND_ZC`/`SENDMSG_ZC` on a
  kTLS socket is structurally impossible: any ULP clears `SOCK_SUPPORT_ZC`
  (`net/ipv4/tcp_ulp.c:139-140`) and both `io_send_zc` (`io_uring/net.c:1377`)
  and `io_sendmsg_zc` (`:1445`) refuse on that bit. Moot for the design,
  because ordinary `Send` already pins the pages — see 3.6.
- **Question (a) → [P-23].** A plain `IORING_OP_SEND` on a kTLS fixed
  descriptor round-trips correctly: `rx_bytes == sent`, `rx_corrupt_reads=0`,
  every arm.

**Still unverified. Nothing below has been measured, and none of it should be
quoted as a result:**

1. **[U-3] The cost of a copy at 400/800 GbE.** Inherited unverified from the
   previous design doc and still unverified. One measured number exists
   (~3.2 GiB/s/core at 200 GbE); do not extrapolate a core count from it.
2. **[U-4] Whether kTLS helps at ringline's actual payload sizes.** Everything
   here scales with payload; ringline's benchmarks are small-op dominated.
   **G0 measured the mechanism, not the benefit** — it counted kernel branches
   at 4 KiB–256 KiB, which says nothing about whether removing those passes is
   visible at 64 B. This is now the largest open question on the win side.
3. **The entire receive-path analysis.** `darg.zc` was never traced;
   `TLS_RX_EXPECT_NO_PAD` was shown only to be *accepted* [P-16], not to change
   the copy count. The same kprobe technique pointed at `tls_decrypt_sg` and
   the `darg.zc` decision (`tls_sw.c:2031-2033`) would settle it as cheaply as
   G0 settled the send side. It has not been done.
4. **[U-5] Whether G0 reproduces on the 6.12.90 target.** G0 ran on **hv02**,
   Linux **6.12.74** — not hv01's 6.12.90 — because hv01 has been stuck `busy`
   with no scheduled job for ~8 h. Same series, and the v6.12 source cited
   throughout this document is identical for every function traced, so the
   result is expected to hold. "Expected to hold" is this document's phrase for
   unverified. Rerun on `z2.baremetal` when hv01 frees.
5. **Whether any *other* in-tree driver implements TLS offload under a filename
   the search missed.** The four in the table were confirmed by reading their
   `tlsdev_ops` assignments; the filename sweep that found them ran against a
   GitHub tree listing reporting `truncated: true`. The negative results for
   i40e/ice/ena are solid (whole directories fetched and grepped, plus the hv01
   `ethtool` measurement); the *completeness* of the positive list is
   high-confidence, not certain.
6. **kTLS behaviour under io_uring multishot `recvmsg` specifically.** The
   probes used blocking `recvmsg`. Multishot re-arm across an `EIO`, and
   `MSG_CTRUNC` sizing with a shared per-worker msghdr, are untested. Given
   that `MSG_WAITALL` turned out to be refused on the send side [P-19], assume
   nothing about flag acceptance on the recv side — probe it before designing
   around it.
7. **Whether the AWS rigs have `CONFIG_TLS` at all.** hv01 and hv02 both do
   (hv02 ran G0). The AWS hosts were never probed; `TLS_HW` is absent there
   regardless [P-7], but software kTLS availability is unchecked.
8. **[U-6] Toolchain floor.** hv01 carries a pre-existing rustup at **1.85.0**;
   hv02 had none and rustup installed **1.97.1**. Not the uniform 1.97.1
   assumed earlier — anything built through these jobs must compile on **1.85**
   to run on both hosts. Not a risk, but a constraint that has already bitten
   once (the `E0499` that failed `01a07047`'s second step).

---

## Recommendation

**Do not start kTLS. G0 has run and passed; the decision now turns on G2,
carrying the measured N5 cost — and on N2, N3 and N4, none of which G0
touched.**

The shape of the recommendation is unchanged by G0, and that is the point: G0
was the cheapest way to *falsify* the effort early, not to justify it. It did
not fire, so the question moves on rather than closing.

The case for kTLS is stronger than the previous design doc believed on one
axis and weaker on the other, and the two do not cancel:

- **Stronger, and now measured.** Software kTLS removes 2 of 3 send-path
  passes: `IORING_OP_SEND` on a kTLS socket takes the pinned-pages path
  100% of the time — on a fixed descriptor, and under forced io-wq offload —
  and the copy path is never entered [P-21]. The AEAD reads ringline's pool
  slot directly and the plaintext never enters the kernel. That is a real,
  structural, previously-unclaimed win, and it is no longer a prediction.
  Better still, since ordinary `Send` pins the pages, a `SendGuard` under kTLS
  needs no `SendZc` at all [P-22] — guarded sends could reach **zero**
  userspace passes (3.6).
- **Weaker.** The endpoint the effort was aimed at is gone. `TLS_HW` is not
  zero-copy [P-6] and is unreachable on every machine we own [P-7]. The
  `sendfile` benefit does not compose with ringline's architecture [P-13].
  What is left is a software win whose *benefit* — as opposed to its
  mechanism — is still unmeasured, at payload sizes we do not benchmark [U-4].
  **G0 counted kernel branches at 4 KiB–256 KiB. It did not show that anyone
  goes faster.**

And the cost is high and front-loaded: **kTLS refuses `MSG_WAITALL`** [P-19],
so Domain Invariant 5's mechanism does not survive and the userspace
short-send resubmit loop has to come back for kTLS connections — undoing a
shipped, argued decision; a `RecvMsgMulti` conversion of the TCP recv hot path
on both backends (Large, and colliding with segmented recv); a send-ordering
hazard at the switch that invariant 2 does not currently cover; a
confidentiality-limit counter ringline would have to own; and — decisively for
the only rig we can run this on — **`KeyUpdate` is impossible on kernel 6.12**,
so hv01 can validate the fast path but cannot validate the correctness envelope
G3 demands.

The `MSG_WAITALL` refusal is worth dwelling on as a *method* result: it is a
hard blocker, it contradicts nothing in any prior document because no prior
document considered it, and it took one 150-line probe on hv01 to find. Three
documents' worth of reasoning about kTLS had been written without anyone
putting a kTLS socket on a rig.

So the sequencing is:

1. ~~**Run G0.**~~ ✅ **Done.** Passed, by direct kernel tracing rather than the
   allocation-counter proxy originally specified. N1 did not fire. [P-21]
2. **Next, and still cheap: two more measurements, not any code.**
   - **A recv-side G0.** The same kprobe technique pointed at `tls_decrypt_sg`
     and the `darg.zc` decision (`tls_sw.c:2031-2033`). The RX 2 → 1 claim is
     currently source-only and should not be carried further unmeasured.
   - **Rerun G0 on hv01** (6.12.90) when it frees, to close [U-5].
3. **Then the question that actually decides it: "is the win present at
   1 KiB?"** [U-4]. G0 measured the mechanism, not the benefit. If the win is
   only visible at 256 KiB, kTLS is a feature for a workload ringline does not
   currently have, and it should wait for one. This is a G2-shaped, two-machine
   measurement, and it must carry the **measured** N5 cost [P-24] — 54 short
   sends per 20 logical sends under backpressure — on the same connections.
4. **Only then** scope the implementation — and get a 6.14+ kernel onto a rig
   first, because without rekey the correctness envelope cannot be tested at
   all [P-5].

**The honest summary of where this stands:** the thing that was most likely to
be false turned out to be true, and it was established for the price of one
probe. What is left is not a premise question any more — it is a cost/benefit
question (G2 against N5) and three scope questions (N2, N3, N4), and those are
answered by building or by measuring end to end, not by reading more source.

Two things worth doing **regardless** of the kTLS decision, both cheap. ✅
**Both done** — see §3.2 and the correction blocks in
[`tls-unbuffered-design.md`](tls-unbuffered-design.md).

- ~~Correct every `dangerous_extract_secrets` citation to
  `dangerous_into_kernel_connection`.~~ Done, and it turned out to be more than
  a rename: the old method is on the **buffered** connection types too, so the
  citation never supported the claim that the unbuffered engine is the kTLS
  prerequisite. The replacement is unbuffered-only, so the claim is true — for
  a reason no ringline document had. It also solves two of the problems the
  journal listed as costs (key updates, session tickets).
- ~~Correct `tls-unbuffered-design.md:120-121`'s copy table rows for kTLS.~~
  Done. They were wrong in *opposite* directions, not the same one: software
  kTLS is cheaper than the table claimed (the kernel pins the pages), and
  `TLS_HW` is more expensive (it still copies, and only removes the CPU
  crypto). The row that was wrong in the same direction as the retracted
  1-copy claim was the `TLS_HW` zero — the endpoint that document's 800 GbE
  argument was aimed at.
