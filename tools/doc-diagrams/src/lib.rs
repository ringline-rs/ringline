use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct DiagramSet {
    pub runtime: String,
    pub request_flow: String,
}

struct Claim {
    path: &'static str,
    needle: &'static str,
    meaning: &'static str,
}

const CLAIMS: &[Claim] = &[
    Claim {
        path: "ringline/src/worker.rs",
        needle: "crossbeam_channel::bounded::<(RawFd, SocketAddr)>",
        meaning: "bounded accepted-fd queue",
    },
    Claim {
        path: "ringline/src/worker.rs",
        needle: ".name(format!(\"ringline-worker-{worker_id}\"))",
        meaning: "literal worker thread name",
    },
    Claim {
        path: "ringline/src/worker.rs",
        needle: ".name(\"ringline-acceptor\".to_string())",
        meaning: "literal acceptor thread name",
    },
    Claim {
        path: "ringline/src/worker.rs",
        needle: "event_loop.prepare_run()",
        meaning: "workers prepare before launch commits",
    },
    Claim {
        path: "ringline/src/acceptor.rs",
        needle: "try_send((fd, peer_addr))",
        meaning: "acceptor never blocks on a full worker queue",
    },
    Claim {
        path: "ringline/src/acceptor.rs",
        needle: "config.worker_wake_handles[worker_idx].wake()",
        meaning: "acceptor wakes the selected worker",
    },
    Claim {
        path: "ringline/src/backend/uring/ring.rs",
        needle: "submit_and_wait(&self, min_complete: u32)",
        meaning: "io_uring submit/completion boundary",
    },
    Claim {
        path: "ringline/src/backend/uring/event_loop.rs",
        needle: "fn spawn_accept_task",
        meaning: "io_uring connection task creation",
    },
    Claim {
        path: "ringline/src/backend/mio/event_loop.rs",
        needle: "fn spawn_accept_task",
        meaning: "Mio connection task creation",
    },
    Claim {
        path: "ringline/src/backend/mio/event_loop.rs",
        needle: ".poll(&mut self.driver.events",
        meaning: "Mio readiness wait",
    },
    Claim {
        path: "ringline/src/runtime/io.rs",
        needle: "pub fn with_data<F:",
        meaning: "buffered receive API",
    },
    Claim {
        path: "ringline/src/runtime/mod.rs",
        needle: "pub(crate) fn wake_recv",
        meaning: "receive completion wakes task owner",
    },
    Claim {
        path: "ringline/src/handler.rs",
        needle: "pub queue: VecDeque<BuiltSend>",
        meaning: "per-connection ordered send queue",
    },
    Claim {
        path: "ringline/src/handler.rs",
        needle: "pub in_flight: bool",
        meaning: "one in-flight send per connection",
    },
    Claim {
        path: "ringline/src/tls.rs",
        needle: "HandshakeJustCompleted",
        meaning: "TLS handshake gates application task",
    },
    Claim {
        path: "ringline/src/wakeup.rs",
        needle: "pub(crate) fn create_wake_fd",
        meaning: "cross-thread wake endpoint",
    },
    Claim {
        path: "ringline/src/backend/mio/event_loop.rs",
        needle: "DiskIoPool::start(",
        meaning: "Mio disk I/O pool creation",
    },
    Claim {
        path: "ringline/src/disk_io_pool.rs",
        needle: ".name(format!(\"ringline-disk-io-{i}\"))",
        meaning: "literal Mio disk I/O thread name",
    },
    Claim {
        path: "ringline/src/disk_io_pool.rs",
        needle: "req.wake_handle.wake()",
        meaning: "Mio disk I/O response wake",
    },
    Claim {
        path: "ringline/build.rs",
        needle: "cargo:rustc-cfg=has_io_uring",
        meaning: "compile-time backend selection",
    },
];

/// The kernel floor `ringline/build.rs` enforces for the io_uring backend.
/// Docs that advertise the floor are checked against this same constant so a
/// bump in build.rs cannot leave stale version prose behind.
const MIN_IOURING_KERNEL: (u32, u32) = (6, 0);

/// Docs that state the io_uring kernel floor in prose.
const KERNEL_FLOOR_DOCS: &[&str] = &[
    "README.md",
    "ringline/README.md",
    "docs/architecture.md",
    "docs/io-uring-primer.md",
];

pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("tool crate must be two levels below workspace root")
        .to_path_buf()
}

pub fn verify_source_claims(root: &Path) -> io::Result<()> {
    for claim in CLAIMS {
        let path = root.join(claim.path);
        let source = fs::read_to_string(&path)?;
        if !strip_whitespace(&source).contains(&strip_whitespace(claim.needle)) {
            return Err(io::Error::other(format!(
                "diagram claim drifted: {} ({}) no longer contains {:?} (compared ignoring \
                 whitespace); if the code legitimately changed, update the claim table in \
                 tools/doc-diagrams/src/lib.rs",
                claim.meaning,
                path.display(),
                claim.needle
            )));
        }
    }

    let build = fs::read_to_string(root.join("ringline/build.rs"))?;
    if !build.contains("target_os == \"linux\"") || !build.contains("CARGO_FEATURE_FORCE_MIO") {
        return Err(io::Error::other(
            "backend diagram requires Linux and force-mio compile-time selection",
        ));
    }

    let floor_needle = format!(
        "(major, minor) >= ({}, {})",
        MIN_IOURING_KERNEL.0, MIN_IOURING_KERNEL.1
    );
    if !build.contains(&floor_needle) {
        return Err(io::Error::other(format!(
            "kernel-floor claim drifted: ringline/build.rs no longer checks {floor_needle:?}; \
             update MIN_IOURING_KERNEL in tools/doc-diagrams/src/lib.rs and every doc listed \
             in KERNEL_FLOOR_DOCS"
        )));
    }
    let floor_text = format!("{}.{}", MIN_IOURING_KERNEL.0, MIN_IOURING_KERNEL.1);
    for doc in KERNEL_FLOOR_DOCS {
        let contents = fs::read_to_string(root.join(doc))?;
        if !contents.contains(&floor_text) {
            return Err(io::Error::other(format!(
                "kernel-floor claim drifted: {doc} no longer mentions kernel {floor_text} \
                 while ringline/build.rs enforces it"
            )));
        }
    }

    let worker = fs::read_to_string(root.join("ringline/src/worker.rs"))?;
    require_order(
        &worker,
        "startup_rx.recv()",
        "create_listener(addr, self.config.backlog)",
        "every worker reports readiness before the TCP listener is created",
    )?;
    require_order(
        &worker,
        "create_listener(addr, self.config.backlog)",
        ".name(\"ringline-acceptor\".to_string())",
        "the listener is created before the acceptor thread starts",
    )?;

    let runtime = fs::read_to_string(root.join("ringline/src/runtime/mod.rs"))?;
    require_order_after(
        &runtime,
        "pub(crate) fn wake_recv",
        "self.owner_task[idx].unwrap_or(conn_index)",
        "self.wake_task(task_id)",
        "receive wake resolves and wakes the owning task",
    )?;

    let uring_loop = fs::read_to_string(root.join("ringline/src/backend/uring/event_loop.rs"))?;
    let mio_loop = fs::read_to_string(root.join("ringline/src/backend/mio/event_loop.rs"))?;
    for (source, backend) in [(&uring_loop, "io_uring"), (&mio_loop, "Mio")] {
        require_order_after(
            source,
            "TlsRecvResult::HandshakeJustCompleted",
            "cs.established = true",
            "self.spawn_accept_task(conn_index)",
            &format!("{backend} TLS handshake gates the accepted task"),
        )?;
        require_order_after(
            source,
            "// Drain DNS resolve responses.",
            "rx.try_recv()",
            "deliver_resolve",
            &format!("{backend} resolver responses return through the worker loop"),
        )?;
        require_order_after(
            source,
            "// Drain process spawn responses.",
            "rx.try_recv()",
            "deliver_spawn",
            &format!("{backend} spawn responses return through the worker loop"),
        )?;
        require_order_after(
            source,
            "// Drain blocking responses.",
            "rx.try_recv()",
            "deliver_blocking",
            &format!("{backend} blocking responses return through the worker loop"),
        )?;
    }
    require_order_after(
        &mio_loop,
        "if let Some(ref rx) = self.driver.disk_io_rx",
        "rx.try_recv()",
        "response.seq",
        "Mio drains disk I/O responses in the worker loop",
    )?;
    require_order_after(
        &uring_loop,
        "pub(crate) fn run",
        "submit_and_wait(min_complete)",
        "self.drain_completions()",
        "io_uring waits for and then drains completions",
    )?;
    require_order_after(
        &uring_loop,
        "fn handle_close",
        "self.executor.remove_connection(conn_index)",
        "self.driver.connections.release(conn_index)",
        "io_uring removes the task before recycling the connection slot",
    )?;
    require_order_after(
        &mio_loop,
        "pub(crate) fn run",
        ".poll(&mut self.driver.events",
        "for event in self.driver.events.iter()",
        "Mio polls before dispatching readiness events",
    )?;
    require_order_after(
        &mio_loop,
        "fn drain_pending_closes",
        "self.executor.remove_connection(conn_index)",
        "self.driver.finish_close(conn_index)",
        "Mio removes the task before backend close and slot recycling",
    )?;
    require_order_after(
        &mio_loop,
        "// Plaintext path.",
        "loop {",
        "match stream.read(recv_buf)",
        "Mio drains readable plaintext sockets in a read loop",
    )?;
    require_order_after(
        &mio_loop,
        "match stream.read(recv_buf)",
        "self.executor.wake_recv(conn_index)",
        "Err(ref e) if e.kind() == io::ErrorKind::WouldBlock",
        "Mio makes received bytes visible and drains until EAGAIN",
    )?;
    require_order_after(
        &mio_loop,
        "// 6. Collect wakeups and poll ready tasks.",
        "self.executor.collect_wakeups()",
        "self.poll_ready_tasks()",
        "Mio polls the owner task after collecting receive wakes",
    )?;
    let mio_driver = fs::read_to_string(root.join("ringline/src/backend/mio/driver.rs"))?;
    require_order_after(
        &mio_driver,
        "pub(crate) fn finish_close",
        "self.tcp_streams[idx].take()",
        "self.connections.release(conn_index)",
        "Mio closes the socket before recycling the connection slot",
    )?;

    let manifest = fs::read_to_string(root.join("ringline/Cargo.toml"))?;
    if manifest.contains("crossbeam-deque") {
        return Err(io::Error::other(
            "runtime diagram assumes no work-stealing deque dependency",
        ));
    }
    Ok(())
}

/// Match ignoring all whitespace so a rustfmt reflow cannot break a claim
/// whose code is unchanged.
fn strip_whitespace(input: &str) -> String {
    input.chars().filter(|c| !c.is_whitespace()).collect()
}

fn require_order(source: &str, before: &str, after: &str, meaning: &str) -> io::Result<()> {
    let source = strip_whitespace(source);
    let before_pos = source.find(&strip_whitespace(before)).ok_or_else(|| {
        io::Error::other(format!(
            "diagram claim drifted: missing {before:?} ({meaning}); if the code legitimately \
             changed, update the ordered claims in tools/doc-diagrams/src/lib.rs"
        ))
    })?;
    let after_pos = source.find(&strip_whitespace(after)).ok_or_else(|| {
        io::Error::other(format!(
            "diagram claim drifted: missing {after:?} ({meaning}); if the code legitimately \
             changed, update the ordered claims in tools/doc-diagrams/src/lib.rs"
        ))
    })?;
    if before_pos >= after_pos {
        return Err(io::Error::other(format!(
            "diagram claim drifted: expected {before:?} before {after:?} ({meaning})"
        )));
    }
    Ok(())
}

fn require_order_after(
    source: &str,
    anchor: &str,
    before: &str,
    after: &str,
    meaning: &str,
) -> io::Result<()> {
    let source = strip_whitespace(source);
    let anchor_pos = source.find(&strip_whitespace(anchor)).ok_or_else(|| {
        io::Error::other(format!(
            "diagram claim drifted: missing anchor {anchor:?} ({meaning}); if the code \
             legitimately changed, update the ordered claims in tools/doc-diagrams/src/lib.rs"
        ))
    })?;
    require_order(&source[anchor_pos..], before, after, meaning)
}

fn svg_number(node: roxmltree::Node<'_, '_>, attribute: &str) -> io::Result<f64> {
    node.attribute(attribute)
        .ok_or_else(|| {
            io::Error::other(format!("SVG {} lacks {attribute}", node.tag_name().name()))
        })?
        .parse::<f64>()
        .map_err(|error| io::Error::other(format!("invalid SVG {attribute}: {error}")))
}

fn validate_svg_geometry(svg: &str) -> io::Result<()> {
    let document = roxmltree::Document::parse(svg)
        .map_err(|error| io::Error::other(format!("invalid SVG XML: {error}")))?;
    let root = document.root_element();
    if root.tag_name().name() != "svg" {
        return Err(io::Error::other("diagram root is not svg"));
    }
    let view_box: Vec<f64> = root
        .attribute("viewBox")
        .ok_or_else(|| io::Error::other("SVG lacks viewBox"))?
        .split_whitespace()
        .map(|value| {
            value
                .parse::<f64>()
                .map_err(|error| io::Error::other(format!("invalid SVG viewBox: {error}")))
        })
        .collect::<io::Result<_>>()?;
    if view_box.len() != 4 || view_box[2] <= 0.0 || view_box[3] <= 0.0 {
        return Err(io::Error::other(
            "SVG viewBox must contain x y width height",
        ));
    }
    let (min_x, min_y, max_x, max_y) = (
        view_box[0],
        view_box[1],
        view_box[0] + view_box[2],
        view_box[1] + view_box[3],
    );
    let bounded = |value: f64, low: f64, high: f64| value >= low && value <= high;
    let check = |name: &str, left: f64, top: f64, right: f64, bottom: f64| {
        if bounded(left, min_x, max_x)
            && bounded(right, min_x, max_x)
            && bounded(top, min_y, max_y)
            && bounded(bottom, min_y, max_y)
        {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "SVG {name} is outside viewBox: ({left}, {top})..({right}, {bottom})"
            )))
        }
    };

    for node in root.descendants().filter(|node| node.is_element()) {
        match node.tag_name().name() {
            "rect"
                if node
                    .attribute("width")
                    .is_some_and(|value| value.ends_with('%')) => {}
            "rect" => {
                let x = svg_number(node, "x")?;
                let y = svg_number(node, "y")?;
                check(
                    "rect",
                    x,
                    y,
                    x + svg_number(node, "width")?,
                    y + svg_number(node, "height")?,
                )?;
            }
            "circle" => {
                let x = svg_number(node, "cx")?;
                let y = svg_number(node, "cy")?;
                let radius = svg_number(node, "r")?;
                check("circle", x - radius, y - radius, x + radius, y + radius)?;
            }
            "line" => {
                let x1 = svg_number(node, "x1")?;
                let y1 = svg_number(node, "y1")?;
                let x2 = svg_number(node, "x2")?;
                let y2 = svg_number(node, "y2")?;
                check("line", x1.min(x2), y1.min(y2), x1.max(x2), y1.max(y2))?;
            }
            "text" => {
                let x = svg_number(node, "x")?;
                let y = svg_number(node, "y")?;
                let size = svg_number(node, "font-size")?;
                let estimated_width =
                    node.text().unwrap_or_default().chars().count() as f64 * size * 0.62;
                let (left, right) = if node.attribute("text-anchor") == Some("middle") {
                    (x - estimated_width / 2.0, x + estimated_width / 2.0)
                } else {
                    (x, x + estimated_width)
                };
                check("text", left, y - size, right, y + size * 0.25)?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn render_all(root: &Path) -> io::Result<DiagramSet> {
    verify_source_claims(root)?;
    let diagrams = DiagramSet {
        runtime: render_runtime(),
        request_flow: render_request_flow(),
    };
    validate_svg_geometry(&diagrams.runtime)?;
    validate_svg_geometry(&diagrams.request_flow)?;
    Ok(diagrams)
}

pub fn write_all(root: &Path, check: bool) -> io::Result<()> {
    let diagrams = render_all(root)?;
    let output = root.join("docs/diagrams");
    let files = [
        (output.join("runtime.svg"), diagrams.runtime),
        (output.join("request-flow.svg"), diagrams.request_flow),
    ];

    if check {
        for (path, expected) in files {
            // Normalize line endings so an autocrlf checkout cannot fail the
            // byte comparison forever (.gitattributes also pins these files
            // to LF).
            let actual = fs::read_to_string(&path)?.replace("\r\n", "\n");
            if actual != expected {
                let (line, expected_line, actual_line) = first_divergence(&expected, &actual);
                return Err(io::Error::other(format!(
                    "{} is stale at line {line}: expected {expected_line:?}, found \
                     {actual_line:?}; regenerate with `cargo run -p doc-diagrams` (generator \
                     and claim tables: tools/doc-diagrams/src/lib.rs)",
                    path.display()
                )));
            }
        }
    } else {
        fs::create_dir_all(output)?;
        for (path, contents) in files {
            fs::write(path, contents)?;
        }
    }
    Ok(())
}

/// Locate the first line where two renderings differ, for actionable
/// stale-diagram errors.
fn first_divergence(expected: &str, actual: &str) -> (usize, String, String) {
    let mut expected_lines = expected.lines();
    let mut actual_lines = actual.lines();
    let mut line = 0;
    loop {
        line += 1;
        match (expected_lines.next(), actual_lines.next()) {
            (Some(e), Some(a)) if e == a => continue,
            (e, a) => {
                return (
                    line,
                    e.unwrap_or("<end of file>").to_string(),
                    a.unwrap_or("<end of file>").to_string(),
                );
            }
        }
    }
}

fn render_runtime() -> String {
    let mut svg = canvas(1280, 760, "Ringline runtime topology");
    text(
        &mut svg,
        50,
        55,
        "Runtime startup and connection ownership",
        28,
        false,
    );
    text(
        &mut svg,
        50,
        84,
        "Workers become ready before the listener exists.",
        16,
        false,
    );

    external_box(&mut svg, 60, 135, 190, 70, "caller / application");
    box_(
        &mut svg,
        310,
        125,
        220,
        90,
        "RinglineBuilder",
        "#CCEBC5",
        false,
    );
    arrow(&mut svg, 250, 170, 310, 170, "launch");

    box_(
        &mut svg,
        610,
        105,
        250,
        70,
        "prepare N workers",
        "#CCEBC5",
        false,
    );
    box_(
        &mut svg,
        610,
        205,
        250,
        70,
        "bind + listen",
        "#CCEBC5",
        false,
    );
    arrow(&mut svg, 530, 170, 610, 140, "spawn");
    arrow(&mut svg, 735, 175, 735, 205, "all ready");

    box_(
        &mut svg,
        935,
        205,
        260,
        70,
        "ringline-acceptor",
        "#F2F2F2",
        true,
    );
    arrow(&mut svg, 860, 240, 935, 240, "listener fd");
    external_box(&mut svg, 935, 105, 260, 60, "network peers");
    arrow(&mut svg, 1065, 165, 1065, 205, "TCP bytes");

    queue(&mut svg, 930, 345, 270, 62, "bounded fd queue + wake");
    arrow(&mut svg, 1065, 275, 1065, 345, "try_send + wake");

    group_box(
        &mut svg,
        540,
        470,
        660,
        190,
        "ringline-worker-i",
        "#F2F2F2",
        true,
    );
    box_(
        &mut svg,
        575,
        520,
        180,
        80,
        "backend Driver",
        "#CCEBC5",
        false,
    );
    box_(&mut svg, 780, 520, 170, 80, "Executor", "#CCEBC5", false);
    box_(
        &mut svg,
        975,
        520,
        190,
        80,
        "handler instance",
        "#FBB4AE",
        false,
    );
    arrow(&mut svg, 1065, 407, 1065, 470, "accepted fd");
    arrow(&mut svg, 755, 560, 780, 560, "events");
    arrow(&mut svg, 950, 560, 975, 560, "poll task");

    group_box(
        &mut svg,
        60,
        470,
        390,
        190,
        "optional auxiliary pools",
        "#F2F2F2",
        false,
    );
    text(&mut svg, 90, 520, "ringline-resolver-i", 17, true);
    text(&mut svg, 90, 555, "ringline-spawner-i", 17, true);
    text(&mut svg, 90, 590, "ringline-blocking-i", 17, true);
    text(&mut svg, 90, 625, "ringline-disk-io-i (Mio)", 17, true);
    arrow(&mut svg, 450, 565, 540, 565, "response queue + wake");

    text(
        &mut svg,
        50,
        720,
        "No shared Driver • no work stealing • no cross-worker task migration",
        16,
        false,
    );
    svg.push_str("</svg>\n");
    svg
}

fn paired_edge_offsets(midpoint: u32, separation: u32) -> (u32, u32) {
    let half = separation / 2;
    (midpoint - half, midpoint + half)
}

#[derive(Clone, Copy)]
enum RequestBackend {
    IoUring,
    Mio,
}

impl RequestBackend {
    fn panel_label(self) -> &'static str {
        match self {
            Self::IoUring => "io_uring request flow",
            Self::Mio => "Mio request flow",
        }
    }

    fn wait_label(self) -> &'static str {
        match self {
            Self::IoUring => "submit_and_wait + CQE",
            Self::Mio => "poll readiness\nread until EAGAIN",
        }
    }

    fn submit_label(self) -> &'static str {
        match self {
            Self::IoUring => "SQE",
            Self::Mio => "interest",
        }
    }

    fn completion_label(self) -> &'static str {
        match self {
            Self::IoUring => "CQE",
            Self::Mio => "readiness",
        }
    }
}

fn render_request_flow() -> String {
    let mut svg = canvas(1460, 1620, "Ringline connection and request flow");
    text(
        &mut svg,
        50,
        55,
        "One connection, one long-lived task",
        28,
        false,
    );
    text(
        &mut svg,
        50,
        84,
        "Each backend has its own event path into the same portable task lifecycle.",
        16,
        false,
    );

    render_request_flow_panel(&mut svg, 0, RequestBackend::IoUring);
    render_request_flow_panel(&mut svg, 800, RequestBackend::Mio);
    svg.push_str("</svg>\n");
    svg
}

fn render_request_flow_panel(svg: &mut String, offset: u32, backend: RequestBackend) {
    let y = |value: u32| value + offset;
    svg.push_str(&format!(
        "<text x=\"730\" y=\"{}\" text-anchor=\"middle\" data-role=\"backend-panel\" font-family=\"sans-serif\" font-size=\"21\" font-weight=\"bold\" fill=\"#222\">{}</text>\n",
        y(115),
        escape(backend.panel_label())
    ));

    lane(svg, 70, y(160), 250, 590, "connection owner");
    lane(svg, 350, y(160), 250, 590, "portable runtime");
    lane(svg, 630, y(160), 350, 590, "backend");
    lane(svg, 1010, y(160), 380, 590, "kernel / peer");

    stage(
        svg,
        655,
        y(190),
        300,
        54,
        "1",
        "accept fd + allocate slot",
        "#CCEBC5",
    );
    stage(svg, 375, y(270), 200, 54, "2", "TLS handshake?", "#CCEBC5");
    stage(svg, 95, y(350), 200, 54, "3", "on_accept task", "#FBB4AE");
    stage(
        svg,
        375,
        y(430),
        200,
        54,
        "4",
        "with_data / park",
        "#FBB4AE",
    );
    stage(
        svg,
        655,
        y(510),
        300,
        74,
        "5",
        backend.wait_label(),
        "#CCEBC5",
    );
    stage(
        svg,
        375,
        y(600),
        200,
        54,
        "6",
        "schedule owner task",
        "#CCEBC5",
    );
    stage(svg, 95, y(680), 200, 54, "7", "parse + send", "#FBB4AE");

    // Connector pairs center on the midpoint of the stage edge they attach
    // to: stage 5 spans y(510)..y(510)+74, stage 7 spans y(680)..y(680)+54.
    let (backend_upper, backend_lower) = paired_edge_offsets(y(510) + 74 / 2, 24);
    let (parse_upper, parse_lower) = paired_edge_offsets(y(680) + 54 / 2, 20);

    arrow(svg, 1100, y(217), 955, y(217), "accepted fd");
    arrow(svg, 655, y(230), 575, y(297), "generation-tagged ConnCtx");
    arrow(svg, 475, y(324), 195, y(350), "established");
    arrow(svg, 295, y(377), 375, y(457), "await bytes");
    arrow(svg, 575, y(457), 655, backend_upper, "arm receive");
    arrow(
        svg,
        955,
        backend_upper,
        1090,
        backend_upper,
        backend.submit_label(),
    );
    arrow_with_label_offset(
        svg,
        1090,
        backend_lower,
        955,
        backend_lower,
        backend.completion_label(),
        -18.0,
    );
    arrow(svg, 655, backend_lower, 575, y(627), "completion");
    arrow(svg, 375, y(627), 295, parse_upper, "ready task");

    queue(
        svg,
        650,
        y(675),
        310,
        62,
        "per-connection ordered send queue",
    );
    arrow(svg, 295, parse_lower, 650, y(706), "response");
    arrow(svg, 960, y(706), 1090, y(706), "one send in flight");
    external_box(svg, 1090, y(660), 250, 80, "peer socket");
    centered(
        svg,
        730,
        y(780),
        "return/panic → deferred close → slot generation increments",
        15,
        false,
    );
}

fn canvas(width: u32, height: u32, title: &str) -> String {
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}\" height=\"{height}\" viewBox=\"0 0 {width} {height}\" role=\"img\" aria-labelledby=\"title desc\">\n<title id=\"title\">{}</title>\n<desc id=\"desc\">Generated from assertions against Ringline source code.</desc>\n<defs><marker id=\"arrow\" viewBox=\"0 0 10 10\" refX=\"9\" refY=\"5\" markerWidth=\"7\" markerHeight=\"7\" orient=\"auto-start-reverse\"><path d=\"M 0 0 L 10 5 L 0 10 z\" fill=\"#4D4D4D\"/></marker></defs>\n<rect width=\"100%\" height=\"100%\" fill=\"white\"/>\n",
        escape(title)
    )
}

#[allow(clippy::too_many_arguments)]
fn box_(svg: &mut String, x: u32, y: u32, w: u32, h: u32, label: &str, fill: &str, literal: bool) {
    svg.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" rx=\"12\" fill=\"{fill}\" stroke=\"#4D4D4D\" stroke-width=\"1.4\"/>\n"));
    centered(svg, x + w / 2, y + h / 2 + 6, label, 17, literal);
}

#[allow(clippy::too_many_arguments)]
fn group_box(
    svg: &mut String,
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    label: &str,
    fill: &str,
    literal: bool,
) {
    svg.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" rx=\"12\" fill=\"{fill}\" stroke=\"#4D4D4D\" stroke-width=\"1.4\"/>\n"));
    let family = if literal { "monospace" } else { "sans-serif" };
    svg.push_str(&format!("<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" data-role=\"group-label\" font-family=\"{family}\" font-size=\"17\" fill=\"#222\">{}</text>\n", x + w / 2, y - 18, escape(label)));
}

fn external_box(svg: &mut String, x: u32, y: u32, w: u32, h: u32, label: &str) {
    svg.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" rx=\"12\" fill=\"white\" stroke=\"#4D4D4D\" stroke-width=\"2.4\" stroke-dasharray=\"8 5\"/>\n"));
    centered(svg, x + w / 2, y + h / 2 + 6, label, 17, false);
}

fn queue(svg: &mut String, x: u32, y: u32, w: u32, h: u32, label: &str) {
    svg.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" fill=\"#EDEDED\" stroke=\"#4D4D4D\" stroke-width=\"1.4\"/>\n"));
    for i in 1..6 {
        let xx = x + (w * i / 6);
        svg.push_str(&format!(
            "<line x1=\"{xx}\" y1=\"{y}\" x2=\"{xx}\" y2=\"{}\" stroke=\"#9E9E9E\"/>\n",
            y + h
        ));
    }
    centered(svg, x + w / 2, y + h / 2 + 6, label, 15, false);
}

fn lane(svg: &mut String, x: u32, y: u32, w: u32, h: u32, label: &str) {
    svg.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" fill=\"#F7F7F7\" stroke=\"#BDBDBD\"/>\n"));
    svg.push_str(&format!("<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" data-role=\"lane-label\" font-family=\"sans-serif\" font-size=\"17\" fill=\"#222\">{}</text>\n", x + w / 2, y - 13, escape(label)));
}

#[allow(clippy::too_many_arguments)]
fn stage(svg: &mut String, x: u32, y: u32, w: u32, h: u32, number: &str, label: &str, fill: &str) {
    svg.push_str(&format!("<rect x=\"{x}\" y=\"{y}\" width=\"{w}\" height=\"{h}\" rx=\"12\" fill=\"{fill}\" stroke=\"#4D4D4D\" stroke-width=\"1.4\"/>\n"));
    svg.push_str(&format!(
        "<circle cx=\"{}\" cy=\"{}\" r=\"15\" fill=\"white\" stroke=\"#4D4D4D\"/>\n",
        x + 25,
        y + 25
    ));
    centered(svg, x + 25, y + 31, number, 14, false);
    let lines: Vec<_> = label.split('\n').collect();
    let line_span = (lines.len().saturating_sub(1) as u32) * 20;
    let first_baseline = y + h / 2 + 6 - line_span / 2;
    for (i, line) in lines.into_iter().enumerate() {
        centered(
            svg,
            x + w / 2 + 12,
            first_baseline + (i as u32 * 20),
            line,
            15,
            false,
        );
    }
}

fn arrow(svg: &mut String, x1: u32, y1: u32, x2: u32, y2: u32, label: &str) {
    arrow_with_label_offset(svg, x1, y1, x2, y2, label, 18.0);
}

#[allow(clippy::too_many_arguments)]
fn arrow_with_label_offset(
    svg: &mut String,
    x1: u32,
    y1: u32,
    x2: u32,
    y2: u32,
    label: &str,
    label_offset: f64,
) {
    svg.push_str(&format!("<line x1=\"{x1}\" y1=\"{y1}\" x2=\"{x2}\" y2=\"{y2}\" stroke=\"#4D4D4D\" stroke-width=\"1.4\" marker-end=\"url(#arrow)\"/>\n"));
    if !label.is_empty() {
        let dx = f64::from(x2) - f64::from(x1);
        let dy = f64::from(y2) - f64::from(y1);
        let length = dx.hypot(dy);
        let (mut normal_x, mut normal_y) = (dy / length, -dx / length);
        if normal_y > 0.0 || (normal_y.abs() < f64::EPSILON && normal_x < 0.0) {
            normal_x = -normal_x;
            normal_y = -normal_y;
        }
        let x = ((f64::from(x1 + x2) / 2.0) + normal_x * label_offset).round() as u32;
        let y = ((f64::from(y1 + y2) / 2.0) + normal_y * label_offset + 5.0).round() as u32;
        svg.push_str(&format!(
            concat!(
                "<text x=\"{}\" y=\"{}\" text-anchor=\"middle\" ",
                "data-role=\"arrow-label\" font-family=\"sans-serif\" font-size=\"13\" ",
                "fill=\"#222\" stroke=\"white\" stroke-width=\"6\" stroke-linejoin=\"round\" ",
                "paint-order=\"stroke\">{}</text>\n"
            ),
            x,
            y,
            escape(label)
        ));
    }
}

fn centered(svg: &mut String, x: u32, y: u32, label: &str, size: u32, literal: bool) {
    let family = if literal { "monospace" } else { "sans-serif" };
    svg.push_str(&format!("<text x=\"{x}\" y=\"{y}\" text-anchor=\"middle\" font-family=\"{family}\" font-size=\"{size}\" fill=\"#222\">{}</text>\n", escape(label)));
}

fn text(svg: &mut String, x: u32, y: u32, label: &str, size: u32, literal: bool) {
    let family = if literal { "monospace" } else { "sans-serif" };
    svg.push_str(&format!("<text x=\"{x}\" y=\"{y}\" font-family=\"{family}\" font-size=\"{size}\" fill=\"#222\">{}</text>\n", escape(label)));
}

fn escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_claims_match_ringline_runtime() {
        let root = workspace_root();
        verify_source_claims(&root).unwrap();
    }

    #[test]
    fn generated_diagrams_are_stable_and_complete() {
        let root = workspace_root();
        let first = render_all(&root).unwrap();
        let second = render_all(&root).unwrap();
        assert_eq!(first.runtime, second.runtime);
        assert_eq!(first.request_flow, second.request_flow);
        assert!(first.runtime.contains("ringline-acceptor"));
        assert!(first.runtime.contains("ringline-worker-i"));
        assert!(first.request_flow.contains("submit_and_wait"));
        assert!(first.request_flow.contains("on_accept"));
        assert_eq!(first.runtime.matches("<svg").count(), 1);
        assert_eq!(first.runtime.matches("</svg>").count(), 1);
        assert_eq!(first.request_flow.matches("<svg").count(), 1);
        assert_eq!(first.request_flow.matches("</svg>").count(), 1);
    }

    #[test]
    fn ordered_claims_reject_semantic_drift() {
        let source = "anchor then after then before";
        assert!(require_order_after(source, "anchor", "before", "after", "test").is_err());
        assert!(
            require_order_after("anchor before after", "anchor", "before", "after", "test").is_ok()
        );
    }

    #[test]
    fn generated_diagrams_are_valid_svg_with_bounded_geometry() {
        let diagrams = render_all(&workspace_root()).unwrap();
        validate_svg_geometry(&diagrams.runtime).unwrap();
        validate_svg_geometry(&diagrams.request_flow).unwrap();

        let off_canvas = diagrams.runtime.replace("x=\"60\"", "x=\"9999\"");
        assert!(validate_svg_geometry(&off_canvas).is_err());
        assert!(validate_svg_geometry("<svg>").is_err());
    }

    #[test]
    fn arrow_labels_are_centered_with_connector_clearance() {
        let mut horizontal = String::new();
        arrow(&mut horizontal, 100, 100, 200, 100, "horizontal");
        assert!(
            horizontal
                .contains("x=\"150\" y=\"87\" text-anchor=\"middle\" data-role=\"arrow-label\"")
        );
        assert!(horizontal.contains("paint-order=\"stroke\""));

        let mut vertical = String::new();
        arrow(&mut vertical, 100, 100, 100, 200, "vertical");
        assert!(
            vertical
                .contains("x=\"118\" y=\"155\" text-anchor=\"middle\" data-role=\"arrow-label\"")
        );

        let mut reverse = String::new();
        arrow(&mut reverse, 200, 100, 100, 100, "reverse");
        assert!(
            reverse.contains("x=\"150\" y=\"87\" text-anchor=\"middle\" data-role=\"arrow-label\"")
        );
    }

    #[test]
    fn multiline_stage_labels_are_centered_as_a_group() {
        let mut svg = String::new();
        stage(&mut svg, 100, 100, 300, 74, "5", "first\nsecond", "#fff");
        assert!(svg.contains("x=\"262\" y=\"133\""));
        assert!(svg.contains("x=\"262\" y=\"153\""));
    }

    #[test]
    fn paired_connectors_are_symmetric_around_edge_midpoint() {
        // Stage 5 spans y=510..584, so its edge midpoint is 547; stage 7
        // spans y=680..734, midpoint 707.
        assert_eq!(paired_edge_offsets(547, 24), (535, 559));
        assert_eq!(paired_edge_offsets(707, 20), (697, 717));

        let diagram = render_request_flow();
        for coordinate in [
            "y2=\"535\"",
            "y1=\"559\"",
            "y2=\"697\"",
            "y1=\"717\"",
            "y2=\"1335\"",
            "y1=\"1359\"",
            "y2=\"1497\"",
            "y1=\"1517\"",
        ] {
            assert!(diagram.contains(coordinate), "missing {coordinate}");
        }
        for (label, y) in [("CQE", 582), ("readiness", 1382)] {
            let line = diagram
                .lines()
                .find(|line| line.ends_with(&format!(">{label}</text>")))
                .unwrap();
            assert!(line.contains(&format!("y=\"{y}\"")), "{line}");
        }
    }

    #[test]
    fn request_flow_uses_separate_io_uring_and_mio_panels() {
        let diagram = render_request_flow();
        assert_eq!(diagram.matches("data-role=\"backend-panel\"").count(), 2);
        let uring = diagram.find("io_uring request flow").unwrap();
        let mio = diagram.find("Mio request flow").unwrap();
        assert!(uring < mio, "io_uring panel must be above Mio");
        assert_eq!(diagram.matches("submit_and_wait + CQE").count(), 1);
        assert_eq!(diagram.matches("read until EAGAIN").count(), 1);
        assert_eq!(diagram.matches("schedule owner task").count(), 2);
        assert!(
            !diagram.contains("wake_recv + poll</text>"),
            "task polling must not be confused with Mio readiness polling"
        );
        assert!(
            !diagram.contains("io_uring: submit_and_wait + CQE\nMio: poll + readiness"),
            "backend operations must not share a stage"
        );
        assert_eq!(diagram.matches("data-role=\"lane-label\"").count(), 8);
    }

    #[test]
    fn primer_separates_modeled_costs_from_backend_independent_design() {
        let primer = fs::read_to_string(workspace_root().join("docs/io-uring-primer.md")).unwrap();
        for expected in [
            "Worked example, not benchmark data",
            "10,019,532",
            "Approximate userspace total shown",
            "does not introduce pooling",
        ] {
            assert!(
                primer.contains(expected),
                "missing primer contract: {expected}"
            );
        }
    }

    #[test]
    fn nested_layers_separate_parent_labels_and_contain_children() {
        let runtime = render_runtime();
        for expected in [
            "x=\"870\" y=\"452\" text-anchor=\"middle\" data-role=\"group-label\" font-family=\"monospace\" font-size=\"17\" fill=\"#222\">ringline-worker-i",
            "x=\"255\" y=\"452\" text-anchor=\"middle\" data-role=\"group-label\" font-family=\"sans-serif\" font-size=\"17\" fill=\"#222\">optional auxiliary pools",
        ] {
            assert!(
                runtime.contains(expected),
                "group label must sit above its children: {expected}"
            );
        }

        let request_flow = render_request_flow();
        assert_eq!(request_flow.matches("data-role=\"lane-label\"").count(), 8);
        assert_eq!(request_flow.matches("height=\"590\"").count(), 8);
        for y in [660, 1460] {
            let peer = format!("x=\"1090\" y=\"{y}\" width=\"250\" height=\"80\"");
            assert!(
                request_flow.contains(&peer),
                "peer socket box must fit inside its parent lane: {peer}"
            );
        }

        // Derive containment from the rendered geometry rather than
        // restating the renderer's constants: every stage rect must sit
        // fully inside one of the lane rects.
        let document = roxmltree::Document::parse(&request_flow).unwrap();
        let rects: Vec<roxmltree::Node<'_, '_>> = document
            .descendants()
            .filter(|node| node.has_tag_name("rect") && node.attribute("width") != Some("100%"))
            .collect();
        let lanes: Vec<_> = rects
            .iter()
            .filter(|node| node.attribute("fill") == Some("#F7F7F7"))
            .map(|node| rect_bounds(*node))
            .collect();
        let stages: Vec<_> = rects
            .iter()
            .filter(|node| {
                node.attribute("rx").is_some()
                    && matches!(node.attribute("fill"), Some("#CCEBC5" | "#FBB4AE"))
            })
            .map(|node| rect_bounds(*node))
            .collect();
        assert_eq!(lanes.len(), 8);
        assert_eq!(stages.len(), 14);
        for &(left, top, right, bottom) in &stages {
            assert!(
                lanes
                    .iter()
                    .any(|&(lane_left, lane_top, lane_right, lane_bottom)| {
                        left >= lane_left
                            && top >= lane_top
                            && right <= lane_right
                            && bottom <= lane_bottom
                    }),
                "stage ({left}, {top})..({right}, {bottom}) is not contained in any lane"
            );
        }
    }

    fn rect_bounds(node: roxmltree::Node<'_, '_>) -> (f64, f64, f64, f64) {
        let read = |attribute: &str| {
            node.attribute(attribute)
                .expect("rect attribute")
                .parse::<f64>()
                .expect("numeric rect attribute")
        };
        (
            read("x"),
            read("y"),
            read("x") + read("width"),
            read("y") + read("height"),
        )
    }

    #[test]
    fn rendered_mio_disk_pool_has_source_claims() {
        for meaning in [
            "Mio disk I/O pool creation",
            "literal Mio disk I/O thread name",
            "Mio disk I/O response wake",
        ] {
            assert!(
                CLAIMS.iter().any(|claim| claim.meaning == meaning),
                "missing source claim for {meaning}"
            );
        }
    }
}
