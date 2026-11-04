#!/usr/bin/env python3
"""Generate the recv buffer geometry sweep (#416) as SystemsLab experiments.

Design: `docs/recv-buffer-geometry-sweep-design.md`.

Two guests on the X710 LAG — server alone on hv02, load on hv01 — with many
arms per guest boot. Each arm is:

    server:  barrier arm-N-start | exec (timeout -s TERM bench-server) | barrier arm-N-done
    client:  barrier arm-N-start | exec (bench-client)                 | barrier arm-N-done

The server runs in the **foreground** under `timeout -s TERM` rather than as a
detached unit that something has to stop later. SIGTERM is bench-server's
graceful shutdown, so the arm still dumps its runtime counters, the step ends
by itself, and rezolus scopes its recording to exactly that arm instead of
spanning the whole boot and diluting.

Barriers, not a hand-rolled handshake: a barrier is the only construct that
propagates a peer's failure, so a dead client releases the server in seconds
instead of holding a hypervisor until timeout.

Usage:
    ./generate.py --bins-artifact <id> --phase a        # writes chunk TOMLs
    ./generate.py --bins-artifact <id> --phase a --dry  # just print the plan
"""

import argparse
import itertools
import pathlib

KIB = 1024
MIB = 1024 * KIB

# Buffer sizes. Coarse pass walks by 4x; the refine pass fills in the halves
# around whatever knee the coarse pass finds.
COARSE_BUFFERS = [4 * KIB, 16 * KIB, 64 * KIB, 256 * KIB, 1 * MIB]
REFINE_BUFFERS = [8 * KIB, 32 * KIB, 128 * KIB, 512 * KIB]

# Message sizes. `stream` is the unbounded case — the load generator writes
# continuously and never reads, so a buffer of any size fills completely. It is
# the only shape where buffer size is not capped by the payload.
MSG_SIZES = [256, 4 * KIB, 64 * KIB, 256 * KIB, 1 * MIB]

# Ring geometry. Constant memory is today's default (4 MiB/worker): a 1 MiB
# buffer then means a FOUR-deep ring, which is where a big default breaks under
# fan-in. Constant count holds depth and lets memory scale: 1 MiB x 256 is
# 256 MiB per worker.
RING_MEMORY_BYTES = 4 * MIB
RING_CONSTANT_COUNT = 256


def ring_for(policy: str, buffer_size: int) -> int:
    """Buffer count for a policy, clamped to what the config accepts."""
    if policy == "constant-memory":
        count = max(4, RING_MEMORY_BYTES // buffer_size)
    elif policy == "constant-count":
        count = RING_CONSTANT_COUNT
    else:
        raise ValueError(policy)
    # ring_size is a u16 and the ring wants a power of two.
    count = min(count, 32768)
    return 1 << (count.bit_length() - 1)


def arms(phase: str, conns_override: int):
    """Every arm of a phase, as dicts. Order is the caller's problem."""
    buffers = COARSE_BUFFERS if phase == "a" else sorted(COARSE_BUFFERS + REFINE_BUFFERS)
    # Phase A establishes the shape on the two modes that disagree; the others
    # only earn reps if A shows the disagreement is real.
    modes = ["echo", "forward"]
    conns = [conns_override]

    out = []
    for mode, msg, buf, policy, conn in itertools.product(
        modes, MSG_SIZES + ["stream"], buffers, ["constant-memory", "constant-count"], conns
    ):
        # A stream has no message size of its own, and an echo cannot be a
        # stream: skip the combinations that do not exist rather than run them.
        if mode == "forward" and msg != "stream":
            continue
        if mode == "echo" and msg == "stream":
            continue
        # Constant-count and constant-memory are the same arm at the size where
        # they coincide; running it twice buys nothing.
        if policy == "constant-count" and ring_for("constant-memory", buf) == RING_CONSTANT_COUNT:
            continue
        out.append(
            {
                "mode": mode,
                "msg": msg,
                "buffer": buf,
                "ring": ring_for(policy, buf),
                "policy": policy,
                "conns": conn,
            }
        )
    return out


def arm_id(a) -> str:
    msg = a["msg"] if a["msg"] == "stream" else f"{a['msg']}b"
    return f"{a['mode']}-{msg}-buf{a['buffer']}-ring{a['ring']}-c{a['conns']}"


SERVER_ARM = """
[[jobs.steps]]
type = "barrier"
name = "{aid}-start"
timeout = 3600

[[jobs.steps]]
type = "anvil-vm"
mode = "exec"
metrics = true
upload = true
payload = '''
set -uo pipefail
mkdir -p /home/anvil/results
# Foreground under `timeout -s TERM`: SIGTERM is the graceful shutdown, so the
# arm dumps its counters and the step ends on its own. `|| true` because
# `timeout` exits 124 on the deadline it is supposed to hit.
timeout -s TERM {server_secs} /home/anvil/out/bench-server-uring \\
  --runtime ringline --addr {{proxy_ip}}:{{port}} --workers {{workers}} \\
  {server_args} \\
  --metrics-out /home/anvil/results/{aid}.metrics.json \\
  > /home/anvil/results/{aid}.server.log 2>&1 || true
tail -3 /home/anvil/results/{aid}.server.log
'''

[[jobs.steps]]
type = "barrier"
name = "{aid}-done"
timeout = 3600
"""

CLIENT_ARM = """
[[jobs.steps]]
type = "barrier"
name = "{aid}-start"
timeout = 3600

[[jobs.steps]]
type = "anvil-vm"
mode = "exec"
payload = '''
set -uo pipefail
cd /home/anvil && mkdir -p results
for i in $(seq 1 120); do
  (exec 3<>/dev/tcp/{{proxy_ip}}/{{port}}) 2>/dev/null && {{ exec 3>&-; break; }}
  sleep 1
done
ulimit -n 500000
{client_cmd} > results/{aid}.json 2> results/{aid}.log || true
echo "== {aid}"; cat results/{aid}.json
'''

[[jobs.steps]]
type = "barrier"
name = "{aid}-done"
timeout = 3600
"""


def render_chunk(chunk, idx, bins_artifact, phase, warmup, duration, workers):
    server_secs = warmup + duration + 20  # room for connect, teardown, dump
    # One blocking writer per connection is round-robined by its thread, so at
    # high fan-in too few threads makes the load generator the bottleneck and
    # the arm measures the client. hv01 has 56 vCPU; cap well inside it.
    client_threads = min(48, max(16, chunk[0]["conns"] // 32))
    head = f'''# GENERATED by experiments/recv-buffer-sweep/generate.py — do not hand-edit.
# Phase {phase.upper()}, chunk {idx}: {len(chunk)} arms, one guest boot.
# Design: docs/recv-buffer-geometry-sweep-design.md  (#416)
name = "ringline recv-buffer sweep phase-{phase}w{workers} chunk-{idx}"

[params]
bins_artifact = "{bins_artifact}"
image         = "debian-13-6.12"
proxy_ip      = "172.31.0.1"
load_ip       = "172.31.0.2"
port          = "7878"
drain_port    = "7900"
workers       = "{workers}"
warmup        = "{warmup}"
duration      = "{duration}"

# ── server under test: hv02, alone on the box ──────────────────────────────

[[jobs]]
name = "server"
tags = ["z1.baremetal"]

[[jobs.steps]]
type = "anvil-vm"
mode = "start"
shape = "z1.c"
image = "{{image}}"
gpu = false
data_address = "{{proxy_ip}}/24"
boot_timeout = 600

[[jobs.steps]]
type = "anvil-vm"
mode = "exec"
inputs = [{{ artifact = "{{bins_artifact}}", name = "bins.tgz", dest = "/home/anvil" }}]
payload = \'\'\'
set -uo pipefail
cd /home/anvil && tar xzf bins.tgz && chmod +x out/*
sudo sysctl -w net.core.somaxconn=65535 net.ipv4.tcp_max_syn_backlog=65535 \\
  net.core.rmem_max=134217728 net.core.wmem_max=134217728
./out/bench-server-uring --print-backend
\'\'\'
'''

    server_steps = []
    client_steps = []
    for a in chunk:
        aid = arm_id(a)
        if a["mode"] == "forward":
            server_args = (
                f"--proxy-backend {{load_ip}}:{{drain_port}} --proxy-api conn "
                f"--msg-size 16384 --recv-buffer-bytes {a['buffer']} --recv-ring-size {a['ring']}"
            )
            client_cmd = (
                "./out/proxy-load --addr {proxy_ip}:{port} "
                f"--clients {a['conns']} --threads {client_threads} --msg-size 16384 "
                "--warmup {warmup} --duration {duration}"
            )
        else:
            server_args = (
                f"--msg-size {a['msg']} --recv-buffer-bytes {a['buffer']} "
                f"--recv-ring-size {a['ring']}"
            )
            client_cmd = (
                "./out/bench-client --runtime ringline --addr {proxy_ip}:{port} "
                f"--clients {a['conns']} --threads {client_threads} --msg-size {a['msg']} "
                "--warmup {warmup} --duration {duration}"
            )
        server_steps.append(
            SERVER_ARM.format(aid=aid, server_secs=server_secs, server_args=server_args)
        )
        client_steps.append(CLIENT_ARM.format(aid=aid, client_cmd=client_cmd))

    tail_server = '''
[[jobs.steps]]
type = "anvil-vm"
mode = "exec"
upload = true
artifacts = ["/home/anvil/server-results.tgz"]
payload = \'\'\'
tar czf /home/anvil/server-results.tgz -C /home/anvil results
\'\'\'

[[jobs.steps]]
type = "anvil-vm"
mode = "stop"
upload = true

# ── load generator and sink: hv01 ──────────────────────────────────────────

[[jobs]]
name = "load"
tags = ["z2.baremetal"]

[[jobs.steps]]
type = "anvil-vm"
mode = "start"
shape = "z2.c"
image = "{image}"
gpu = false
data_address = "{load_ip}/24"
boot_timeout = 600

[[jobs.steps]]
type = "anvil-vm"
mode = "exec"
inputs = [{ artifact = "{bins_artifact}", name = "bins.tgz", dest = "/home/anvil" }]
payload = \'\'\'
set -uo pipefail
cd /home/anvil && tar xzf bins.tgz && chmod +x out/*
sudo sysctl -w net.core.rmem_max=134217728 net.core.wmem_max=134217728 \\
  net.ipv4.ip_local_port_range="1024 65535"
\'\'\'

# The sink for every forward arm, up for the whole chunk.
[[jobs.steps]]
type = "anvil-vm"
mode = "exec"
detach = true
unit = "proxy-drain"
payload = "exec /home/anvil/out/proxy-drain --addr 0.0.0.0:{drain_port}"
'''

    tail_client = '''
[[jobs.steps]]
type = "anvil-vm"
mode = "exec"
upload = true
artifacts = ["/home/anvil/client-results.tgz"]
payload = \'\'\'
tar czf /home/anvil/client-results.tgz -C /home/anvil results
\'\'\'

[[jobs.steps]]
type = "anvil-vm"
mode = "stop"
upload = true
'''

    return (
        head
        + "".join(server_steps)
        + tail_server
        + "".join(client_steps)
        + tail_client
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bins-artifact", required=True)
    ap.add_argument("--phase", default="a", choices=["a", "b"])
    ap.add_argument("--arms-per-chunk", type=int, default=12)
    # Workers is a first-class knob because an arm that is not server-bound
    # measures the harness. Phase A ran at 8 and every arm had headroom — the
    # echo arms sat at ~8 of 24 cores, the forward arms at ~9 and pinned to the
    # ~22 Gbit/s wire ceiling — so the flat surface said "the server absorbed
    # the difference", not "geometry does not matter". Pick a worker count that
    # saturates.
    ap.add_argument("--workers", type=int, default=2)
    # Connection count is the axis that actually pressures ring *depth*: a
    # 256-deep ring is never stressed by 64 connections, and the constant-memory
    # policy can only fail at fan-in. It is also the more realistic way to
    # saturate a server than cutting it to two workers.
    ap.add_argument("--conns", type=int, default=64)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--duration", type=int, default=20)
    ap.add_argument("--out", default=None)
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    plan = arms(args.phase, args.conns)
    out_dir = pathlib.Path(args.out or pathlib.Path(__file__).parent / f"phase-{args.phase}")
    chunks = [
        plan[i : i + args.arms_per_chunk] for i in range(0, len(plan), args.arms_per_chunk)
    ]

    secs = (args.warmup + args.duration + 20) * len(plan)
    print(f"phase {args.phase}: {len(plan)} arms, {len(chunks)} chunks")
    print(f"  ~{secs // 60} min of measurement + {len(chunks)} guest boots")
    if args.dry:
        for a in plan:
            mem = a["buffer"] * a["ring"] / MIB
            print(f"  {arm_id(a):52s} {a['policy']:16s} {mem:7.1f} MiB/worker")
        return

    out_dir.mkdir(parents=True, exist_ok=True)
    for i, chunk in enumerate(chunks, 1):
        path = out_dir / f"chunk-{i:02d}.toml"
        path.write_text(
            render_chunk(
                chunk, i, args.bins_artifact, args.phase, args.warmup, args.duration, args.workers
            )
        )
        print(f"  wrote {path} ({len(chunk)} arms)")


if __name__ == "__main__":
    main()
