//! An engine that executes nothing: it lets the io_uring driver compile
//! without using the `io_uring` crate (`RINGLINE_STUB_ENGINE=1`). Setup fails, so
//! no other method is reached; each panics if it is.

use std::io;
use std::os::fd::RawFd;

use super::Engine;
use crate::backend::ProvidedBufRing;
use crate::backend::uring::ring::CloseLead;
use crate::backend::uring::sqe::Sqe;
use crate::buffer::fixed::FixedBufferRegistry;
use crate::config::Config;
use crate::error::Error;

/// The engine selected by `RINGLINE_STUB_ENGINE=1`.
pub(crate) struct StubEngine;

impl Engine for StubEngine {
    fn setup(_config: &Config) -> Result<Self, Error> {
        Err(Error::RingSetup(
            "this build has no engine (built with RINGLINE_STUB_ENGINE=1)".into(),
        ))
    }

    unsafe fn push(&mut self, _sqe: &Sqe) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    unsafe fn push_pair(&mut self, _first: &Sqe, _second: &Sqe) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    unsafe fn push_chain(&mut self, _sqes: &[Sqe]) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn submit_and_wait(&self, _min_complete: u32) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn submit_and_wait_timeout(
        &self,
        _min_complete: u32,
        _timeout: std::time::Duration,
    ) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn submit_and_get_events(&self) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn flush(&self) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn completion_pending(&self) -> bool {
        unreachable!("the stub engine fails at setup")
    }

    fn reap(&mut self, _out: &mut Vec<(u64, i32, u32)>) {
        unreachable!("the stub engine fails at setup")
    }

    fn register_files_sparse(&self, _count: u32) -> Result<(), Error> {
        unreachable!("the stub engine fails at setup")
    }

    fn register_files_update(&self, _offset: u32, _fds: &[RawFd]) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn register_buf_ring(&mut self, _provided: &ProvidedBufRing) -> Result<(), Error> {
        unreachable!("the stub engine fails at setup")
    }

    fn unregister_buf_ring(&self, _bgid: u16) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn register_buffers(&self, _registry: &FixedBufferRegistry) -> Result<(), Error> {
        unreachable!("the stub engine fails at setup")
    }

    unsafe fn register_buffers_update_one(&self, _slot: u16, _iov: libc::iovec) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    fn close_lead(&self) -> CloseLead {
        unreachable!("the stub engine fails at setup")
    }

    fn supports_park(&self) -> bool {
        unreachable!("the stub engine fails at setup")
    }

    #[cfg(test)]
    fn inject(&mut self, _user_data: u64, _result: i32, _linked: bool) -> io::Result<()> {
        unreachable!("the stub engine fails at setup")
    }

    #[cfg(test)]
    fn force_push_failures(&mut self, _count: usize) {
        unreachable!("the stub engine fails at setup")
    }
}
