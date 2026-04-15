//! Mio backend event loop — readiness-based I/O dispatch.

use std::io;
use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::config::Config;
use crate::runtime::handler::AsyncEventHandler;

use super::driver::Driver;

/// Mio-based event loop (one per worker thread).
pub(crate) struct AsyncEventLoop<A: AsyncEventHandler> {
    #[allow(dead_code)]
    driver: Driver,
    #[allow(dead_code)]
    handler: A,
}

impl<A: AsyncEventHandler> AsyncEventLoop<A> {
    /// Create a new mio event loop.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: &Config,
        handler: A,
        accept_rx: Option<crossbeam_channel::Receiver<(RawFd, SocketAddr)>>,
        eventfd: RawFd,
        shutdown_flag: Arc<AtomicBool>,
        resolve_rx: Option<crossbeam_channel::Receiver<crate::resolver::ResolveResponse>>,
        resolve_tx: Option<crossbeam_channel::Sender<crate::resolver::ResolveResponse>>,
        resolver: Option<Arc<crate::resolver::ResolverPool>>,
        spawn_rx: Option<crossbeam_channel::Receiver<crate::spawner::SpawnResponse>>,
        spawn_tx: Option<crossbeam_channel::Sender<crate::spawner::SpawnResponse>>,
        spawner: Option<Arc<crate::spawner::SpawnerPool>>,
        blocking_rx: Option<crossbeam_channel::Receiver<crate::blocking::BlockingResponse>>,
        blocking_tx: Option<crossbeam_channel::Sender<crate::blocking::BlockingResponse>>,
        blocking_pool: Option<Arc<crate::blocking::BlockingPool>>,
    ) -> io::Result<Self> {
        let driver = Driver::new(
            config,
            accept_rx,
            eventfd,
            shutdown_flag,
            resolve_rx,
            resolve_tx,
            resolver,
            spawn_rx,
            spawn_tx,
            spawner,
            blocking_rx,
            blocking_tx,
            blocking_pool,
        )?;

        Ok(AsyncEventLoop { driver, handler })
    }

    /// Run the mio event loop until shutdown.
    pub(crate) fn run(&mut self) -> Result<(), crate::error::Error> {
        // TODO: implement mio event loop
        // 1. poll() for events
        // 2. dispatch readable/writable/wake events
        // 3. poll ready tasks
        // 4. check shutdown flag
        Ok(())
    }
}
