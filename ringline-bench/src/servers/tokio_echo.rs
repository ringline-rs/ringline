use std::net::SocketAddr;

pub struct TokioServer {
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    rt_thread: std::thread::JoinHandle<()>,
}

impl TokioServer {
    pub fn start(addr: SocketAddr, workers: usize) -> Self {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();

        let rt_thread = std::thread::spawn(move || {
            let rt = if workers == 1 {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("failed to build tokio runtime")
            } else {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(workers)
                    .enable_all()
                    .build()
                    .expect("failed to build tokio runtime")
            };

            rt.block_on(async move {
                let socket = tokio::net::TcpSocket::new_v4().expect("failed to create socket");
                socket.set_reuseaddr(true).expect("failed to set reuseaddr");
                socket.bind(addr).expect("failed to bind");
                let listener = socket.listen(1024).expect("failed to listen");

                ready_tx.send(()).ok();

                tokio::select! {
                    _ = async {
                        loop {
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
                    } => {}
                    _ = shutdown_rx => {}
                }
            });
        });

        ready_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("tokio server did not start");

        TokioServer {
            shutdown_tx,
            rt_thread,
        }
    }

    pub fn stop(self) {
        self.shutdown_tx.send(()).ok();
        self.rt_thread.join().ok();
    }
}
