use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Manages the lifecycle of a benchmark server.
pub struct BenchmarkServer {
    pub addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl BenchmarkServer {
    pub fn stop(self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.thread {
            h.join().ok();
        }
    }
}

/// Start a TCP echo server for benchmarking.
pub fn start_tcp_echo_server(
    port_manager: &crate::port_manager::PortManager,
    workers: usize,
    msg_size: usize,
) -> Result<BenchmarkServer, String> {
    let addr = port_manager.next_addr(socket2::AddressFamily::Inet);
    let stop = Arc::new(AtomicBool::new(false));

    let rt = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(async move {
            let socket = tokio::net::TcpSocket::new_v4().expect("failed to create socket");
            socket.set_reuseaddr(true).expect("failed to set reuseaddr");
            socket.bind(addr).expect("failed to bind");
            let listener = socket.listen(1024).expect("failed to listen");

            loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(_) => continue,
                };
                stream.set_nodelay(true).ok();

                tokio::spawn(async move {
                    let (mut rd, mut wr) = stream.into_split();
                    tokio::io::copy(&mut rd, &mut wr).await.ok();
                });
            }
        });
    });

    std::thread::sleep(std::time::Duration::from_millis(100));

    Ok(BenchmarkServer {
        addr,
        stop,
        thread: Some(rt),
    })
}
