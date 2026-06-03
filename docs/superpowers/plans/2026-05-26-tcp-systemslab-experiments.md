# TCP Systemslab Experiments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create two systemslab experiment TOML files that run ringline's TCP echo benchmark across a 4-runtime combo matrix on dedicated 10GbE NIC hardware.

**Architecture:** Two self-contained TOML files in `experiments/`. Each uses the systemslab `[matrix]` section to sweep all dimensions (runtime combos × clients × sizes). Per-run: a server job on `z1.n.small` and a client job on `z2.n.small`, coordinated with two barriers (`server-ready`, `benchmark-complete`). Each run uploads a `results.json` artifact matching the `bench-client` JSON output schema.

**Tech Stack:** systemslab TOML experiment format, `bench-server` / `bench-client` binaries from `ringline-bench`, Rust/Cargo build on host.

---

## File Map

| File | Action | Purpose |
|:-----|:-------|:--------|
| `experiments/tcp-closed-loop.toml` | Create | 64-run closed-loop matrix (2×2 runtimes × 4 clients × 4 sizes) |
| `experiments/tcp-open-loop.toml`   | Create | 48-run open-loop saturation sweep (2×2 runtimes × 6 rates × 2 sizes) |

---

## Task 1: `experiments/tcp-closed-loop.toml`

**Files:**
- Create: `experiments/tcp-closed-loop.toml`

- [ ] **Step 1: Create the experiments directory and write the file**

```bash
mkdir -p experiments
```

Write `experiments/tcp-closed-loop.toml` with the following content:

```toml
name = "ringline-tcp {server_runtime}s/{client_runtime}c {clients}conn {msg_size}B"

[params]
ringline_repo    = "https://github.com/brayniac/ringline"
ringline_version = "main"
port             = "7878"
server_workers   = "8"
client_threads   = "8"
warmup_duration  = "3"
test_duration    = "10"

[matrix]
server_runtime = ["ringline", "tokio"]
client_runtime = ["ringline", "tokio"]
clients        = ["1", "10", "50", "200"]
msg_size       = ["64", "512", "4096", "32768"]

# ── Server job (z1.n.small) ────────────────────────────────────────────────

[[jobs]]
name = "server"
tags = ["z1.n.small"]

[[jobs.steps]]
name = "build"
type = "shell"
command = """
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
if [ -d /tmp/ringline ]; then
    cd /tmp/ringline
    git fetch --all
    git checkout {ringline_version}
    git pull --ff-only 2>/dev/null || true
else
    git clone {ringline_repo} /tmp/ringline
    cd /tmp/ringline
    git checkout {ringline_version}
fi
cd /tmp/ringline
cargo build --release --bin bench-server
sudo cp target/release/bench-server /usr/local/bin/bench-server
echo "bench-server build OK: $(bench-server --help 2>&1 | head -1)"
"""

[[jobs.steps]]
name = "tune-system"
type = "shell"
command = """
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo fuser -k {port}/tcp 2>/dev/null || true
sleep 1
echo "System tuning complete"
"""

[[jobs.steps]]
name = "start-server"
type = "shell"
background = true
command = """
ulimit -n 500000
exec bench-server \
    --runtime {server_runtime} \
    --addr 0.0.0.0:{port} \
    --workers {server_workers}
"""

[[jobs.steps]]
name = "wait-for-server"
type = "shell"
command = """
for i in $(seq 1 30); do
    nc -z localhost {port} 2>/dev/null && echo "Server ready on port {port}" && exit 0
    echo "Waiting for server... ($i/30)"
    sleep 1
done
echo "ERROR: bench-server failed to start on port {port}"
exit 1
"""

[[jobs.steps]]
type = "barrier"
name = "server-ready"

[[jobs.steps]]
type = "barrier"
name = "benchmark-complete"

[[jobs.steps]]
name = "server-stats"
type = "shell"
command = """
echo "=== TCP socket stats ==="
ss -s
echo "=== Established connections ==="
ss -tn state established | head -20
"""

# ── Client job (z2.n.small) ────────────────────────────────────────────────

[[jobs]]
name = "client"
tags = ["z2.n.small"]

[[jobs.steps]]
name = "build"
type = "shell"
command = """
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
if [ -d /tmp/ringline ]; then
    cd /tmp/ringline
    git fetch --all
    git checkout {ringline_version}
    git pull --ff-only 2>/dev/null || true
else
    git clone {ringline_repo} /tmp/ringline
    cd /tmp/ringline
    git checkout {ringline_version}
fi
cd /tmp/ringline
cargo build --release --bin bench-client
sudo cp target/release/bench-client /usr/local/bin/bench-client
echo "bench-client build OK: $(bench-client --help 2>&1 | head -1)"
"""

[[jobs.steps]]
type = "barrier"
name = "server-ready"

[[jobs.steps]]
name = "verify-connectivity"
type = "shell"
command = """
echo "SERVER_ADDR=$SERVER_ADDR"
for i in $(seq 1 30); do
    nc -z "$SERVER_ADDR" {port} 2>/dev/null && echo "Server reachable at $SERVER_ADDR:{port}" && exit 0
    echo "Waiting for server to be reachable... ($i/30)"
    sleep 1
done
echo "ERROR: Failed to connect to server at $SERVER_ADDR:{port}"
exit 1
"""

[[jobs.steps]]
name = "run-benchmark"
type = "shell"
command = """
ulimit -n 500000
bench-client \
    --runtime {client_runtime} \
    --addr "$SERVER_ADDR:{port}" \
    --clients {clients} \
    --msg-size {msg_size} \
    --warmup {warmup_duration} \
    --duration {test_duration} \
    --threads {client_threads} \
    > results.json
cat results.json
"""

[[jobs.steps]]
type = "barrier"
name = "benchmark-complete"

[[jobs.steps]]
name = "upload-results"
type = "upload_artifact"
path = "results.json"
```

- [ ] **Step 2: Validate the spec against the systemslab API**

Use the `mcp__systemslab__validate_spec` tool with the file content above.

Expected: `{"valid": true}` or equivalent success response. If validation fails, fix the error reported before continuing.

- [ ] **Step 3: Commit**

```bash
git add experiments/tcp-closed-loop.toml
git commit -m "feat(experiments): add tcp-closed-loop systemslab experiment

64-run matrix: {ringline,tokio} server × {ringline,tokio} client
× {1,10,50,200} connections × {64,512,4096,32768} B messages.
Server on z1.n.small, client on z2.n.small (dedicated x710 NIC ports).

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: `experiments/tcp-open-loop.toml`

**Files:**
- Create: `experiments/tcp-open-loop.toml`

- [ ] **Step 1: Write the file**

Write `experiments/tcp-open-loop.toml` with the following content. It is identical to the closed-loop file except for the `[matrix]`, `[params]`, experiment name, and the `run-benchmark` client step:

```toml
name = "ringline-tcp-open {server_runtime}s/{client_runtime}c {offered_rate}rps {msg_size}B"

[params]
ringline_repo    = "https://github.com/brayniac/ringline"
ringline_version = "main"
port             = "7878"
server_workers   = "8"
client_threads   = "8"
clients          = "200"
max_inflight     = "64"
warmup_duration  = "3"
test_duration    = "30"

[matrix]
server_runtime = ["ringline", "tokio"]
client_runtime = ["ringline", "tokio"]
offered_rate   = ["50000", "100000", "200000", "500000", "1000000", "2000000"]
msg_size       = ["64", "4096"]

# ── Server job (z1.n.small) ────────────────────────────────────────────────

[[jobs]]
name = "server"
tags = ["z1.n.small"]

[[jobs.steps]]
name = "build"
type = "shell"
command = """
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
if [ -d /tmp/ringline ]; then
    cd /tmp/ringline
    git fetch --all
    git checkout {ringline_version}
    git pull --ff-only 2>/dev/null || true
else
    git clone {ringline_repo} /tmp/ringline
    cd /tmp/ringline
    git checkout {ringline_version}
fi
cd /tmp/ringline
cargo build --release --bin bench-server
sudo cp target/release/bench-server /usr/local/bin/bench-server
echo "bench-server build OK: $(bench-server --help 2>&1 | head -1)"
"""

[[jobs.steps]]
name = "tune-system"
type = "shell"
command = """
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo fuser -k {port}/tcp 2>/dev/null || true
sleep 1
echo "System tuning complete"
"""

[[jobs.steps]]
name = "start-server"
type = "shell"
background = true
command = """
ulimit -n 500000
exec bench-server \
    --runtime {server_runtime} \
    --addr 0.0.0.0:{port} \
    --workers {server_workers}
"""

[[jobs.steps]]
name = "wait-for-server"
type = "shell"
command = """
for i in $(seq 1 30); do
    nc -z localhost {port} 2>/dev/null && echo "Server ready on port {port}" && exit 0
    echo "Waiting for server... ($i/30)"
    sleep 1
done
echo "ERROR: bench-server failed to start on port {port}"
exit 1
"""

[[jobs.steps]]
type = "barrier"
name = "server-ready"

[[jobs.steps]]
type = "barrier"
name = "benchmark-complete"

[[jobs.steps]]
name = "server-stats"
type = "shell"
command = """
echo "=== TCP socket stats ==="
ss -s
echo "=== Established connections ==="
ss -tn state established | head -20
"""

# ── Client job (z2.n.small) ────────────────────────────────────────────────

[[jobs]]
name = "client"
tags = ["z2.n.small"]

[[jobs.steps]]
name = "build"
type = "shell"
command = """
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
if [ -d /tmp/ringline ]; then
    cd /tmp/ringline
    git fetch --all
    git checkout {ringline_version}
    git pull --ff-only 2>/dev/null || true
else
    git clone {ringline_repo} /tmp/ringline
    cd /tmp/ringline
    git checkout {ringline_version}
fi
cd /tmp/ringline
cargo build --release --bin bench-client
sudo cp target/release/bench-client /usr/local/bin/bench-client
echo "bench-client build OK: $(bench-client --help 2>&1 | head -1)"
"""

[[jobs.steps]]
type = "barrier"
name = "server-ready"

[[jobs.steps]]
name = "verify-connectivity"
type = "shell"
command = """
echo "SERVER_ADDR=$SERVER_ADDR"
for i in $(seq 1 30); do
    nc -z "$SERVER_ADDR" {port} 2>/dev/null && echo "Server reachable at $SERVER_ADDR:{port}" && exit 0
    echo "Waiting for server to be reachable... ($i/30)"
    sleep 1
done
echo "ERROR: Failed to connect to server at $SERVER_ADDR:{port}"
exit 1
"""

[[jobs.steps]]
name = "run-benchmark"
type = "shell"
command = """
ulimit -n 500000
bench-client \
    --runtime {client_runtime} \
    --addr "$SERVER_ADDR:{port}" \
    --clients {clients} \
    --msg-size {msg_size} \
    --warmup {warmup_duration} \
    --duration {test_duration} \
    --threads {client_threads} \
    --open \
    --rate {offered_rate} \
    --max-inflight {max_inflight} \
    > results.json
cat results.json
"""

[[jobs.steps]]
type = "barrier"
name = "benchmark-complete"

[[jobs.steps]]
name = "upload-results"
type = "upload_artifact"
path = "results.json"
```

- [ ] **Step 2: Validate the spec against the systemslab API**

Use the `mcp__systemslab__validate_spec` tool with the file content above.

Expected: `{"valid": true}` or equivalent success response. If validation fails, fix the error reported before continuing.

- [ ] **Step 3: Commit**

```bash
git add experiments/tcp-open-loop.toml
git commit -m "feat(experiments): add tcp-open-loop systemslab experiment

48-run matrix: {ringline,tokio} server × {ringline,tokio} client
× {50k,100k,200k,500k,1M,2M} rps × {64,4096} B messages.
200 connections, 30s test duration. Saturation sweep to find
where latency blows up vs closed-loop ceiling.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```
