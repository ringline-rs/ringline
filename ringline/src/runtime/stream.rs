//! `ConnStream` — `futures-io` trait adapter for [`Connection`].
//!
//! Wraps a connection in the standard `AsyncRead + AsyncWrite + AsyncBufRead`
//! interface for ecosystem compatibility (codecs, tower, hyper, etc.).
//!
//! The callback-based [`Connection::with_data`] / [`Connection::with_bytes`] API
//! remains the zero-copy hot path for protocol implementations. `ConnStream`
//! is the streaming alternative when trait compatibility matters more than
//! minimising copies on the recv side.
//!
//! # Executor requirement
//!
//! All `poll_*` methods must be called from within the ringline executor
//! (connection task or standalone task). They access the thread-local driver
//! via [`with_state`] and will panic if called from an external runtime.
//!
//! # Waker note
//!
//! ringline does not use [`std::task::Waker`]. The `Context` argument to each
//! `poll_*` method is ignored. Wakeups are driven by the internal waiter-flag
//! system (`recv_waiters`), which is set inside `poll_read` before returning
//! `Poll::Pending`. `poll_write` copies into the send pool with `send_nowait`
//! and does not wait for the send to complete.

use bytes::{Buf, Bytes};
use futures_io::{AsyncBufRead, AsyncRead, AsyncWrite};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use super::io::{Connection, SendHalf, park_recv, with_state};

/// Wraps a [`Connection`] and implements [`AsyncRead`], [`AsyncWrite`], and
/// [`AsyncBufRead`].
///
/// Created via [`ConnStream::new`]. The write half is accessible via
/// [`send_half`](Self::send_half) for operations that have no trait equivalent.
///
/// # Copy profile
///
/// | Trait method | Copies (recv) | Mechanism |
/// |---|---|---|
/// | [`AsyncRead::poll_read`] | 1 | accumulator → caller buf |
/// | [`AsyncBufRead::poll_fill_buf`] | 0 | refcounted `Bytes` slice |
/// | [`AsyncWrite::poll_write`] | 1 | caller buf → send pool |
pub struct ConnStream {
    conn: Connection,
    write_closed: bool,
    /// Cached buffer detached from the accumulator for `AsyncBufRead`.
    /// Held until fully consumed, then dropped so new data flows from
    /// the accumulator on the next `poll_fill_buf`.
    fill_buf: Option<Bytes>,
}

impl ConnStream {
    /// Wrap a [`Connection`] in a streaming adapter.
    pub fn new(conn: Connection) -> Self {
        ConnStream {
            conn,
            write_closed: false,
            fill_buf: None,
        }
    }

    /// The connection's write half.
    ///
    /// Useful for operations without a trait equivalent, such as
    /// [`SendHalf::peer_addr`] or [`SendHalf::close`]. The read half is not
    /// reachable here, because a read would pass bytes cached by
    /// `poll_fill_buf`.
    pub fn send_half(&mut self) -> &mut SendHalf {
        self.conn.send_half()
    }

    /// See [`Connection::eof_truncated`].
    pub fn eof_truncated(&self) -> bool {
        self.conn.eof_truncated()
    }

    /// See [`Connection::recv_arrival`].
    pub fn recv_arrival(&self) -> Option<crate::RecvArrival> {
        self.conn.recv_arrival()
    }

    /// See [`Connection::is_recv_direct`].
    pub fn is_recv_direct(&self) -> bool {
        self.conn.is_recv_direct()
    }

    /// Check whether the connection's recv side is closed.
    fn is_recv_closed(driver: &mut crate::backend::Driver, conn_index: u32) -> bool {
        driver
            .connections
            .get(conn_index)
            .map(|c| c.recv_finished())
            .unwrap_or(true)
    }
}

impl AsyncRead for ConnStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        // Drain any leftover from a prior poll_fill_buf call first.
        if let Some(ref mut cached) = self.fill_buf {
            if !cached.is_empty() {
                let n = cached.len().min(buf.len());
                buf[..n].copy_from_slice(&cached[..n]);
                cached.advance(n);
                if cached.is_empty() {
                    self.fill_buf = None;
                }
                return Poll::Ready(Ok(n));
            }
            self.fill_buf = None;
        }

        let ctx = self.conn.ctx();
        let (conn_index, generation) = (ctx.conn_index, ctx.generation);

        with_state(|driver, executor| {
            // Stale stream: the connection this stream was created for is
            // gone and the slot may belong to a new connection. Reading the
            // accumulator or registering waiters here would leak another
            // connection's bytes and hijack its recv wakeups. Report EOF,
            // mirroring WithDataFuture's generation check.
            if driver.connections.generation(conn_index) != generation {
                return Poll::Ready(Ok(0));
            }
            let data = driver.accumulators.data(conn_index);
            if !data.is_empty() {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                driver.accumulators.consume(conn_index, n);
                return Poll::Ready(Ok(n));
            }

            if Self::is_recv_closed(driver, conn_index) {
                return Poll::Ready(Ok(0));
            }

            park_recv(driver, executor, conn_index, None);
            Poll::Pending
        })
    }
}

impl AsyncBufRead for ConnStream {
    fn poll_fill_buf(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let this = self.get_mut();

        // Return cached buffer if present and non-empty.
        if matches!(this.fill_buf.as_ref(), Some(b) if !b.is_empty()) {
            return Poll::Ready(Ok(this.fill_buf.as_ref().unwrap().as_ref()));
        }

        // Empty or absent — fetch from accumulator.
        this.fill_buf = None;
        let ctx = this.conn.ctx();
        let (conn_index, generation) = (ctx.conn_index, ctx.generation);

        // Try to detach the accumulator as a refcounted Bytes (O(1)).
        let frozen = with_state(|driver, executor| {
            // Stale stream (slot reused) — report EOF; see poll_read.
            if driver.connections.generation(conn_index) != generation {
                return Ok(None);
            }
            let data = driver.accumulators.data(conn_index);
            if !data.is_empty() {
                return Ok(Some(driver.accumulators.take_frozen(conn_index)));
            }

            if Self::is_recv_closed(driver, conn_index) {
                return Ok(None); // EOF
            }

            park_recv(driver, executor, conn_index, None);
            Err(()) // Pending
        });

        match frozen {
            Err(()) => Poll::Pending,
            Ok(None) => {
                // EOF — return empty slice.
                Poll::Ready(Ok(&[]))
            }
            Ok(Some(bytes)) => {
                this.fill_buf = Some(bytes);
                Poll::Ready(Ok(this.fill_buf.as_ref().unwrap().as_ref()))
            }
        }
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        if let Some(ref mut b) = self.fill_buf {
            let advance = amt.min(b.len());
            b.advance(advance);
            if b.is_empty() {
                self.fill_buf = None;
            }
        }
    }
}

impl AsyncWrite for ConnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let ctx = self.conn.ctx();

        // Cap at the send pool's slot size so oversized writes become
        // partial writes (valid per the AsyncWrite contract).
        let max_len = with_state(|driver, _| driver.send_copy_pool.slot_size() as usize);
        let write_len = buf.len().min(max_len);

        match ctx.send_nowait(&buf[..write_len]) {
            Ok(()) => Poll::Ready(Ok(write_len)),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // io_uring submits SQEs directly; no userspace buffer to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.write_closed {
            self.write_closed = true;
            // Half-close: send TCP FIN so the peer sees EOF.
            // The full close happens when the connection task returns and the
            // executor drops the connection slot.
            self.conn.shutdown_write();
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_stream_size() {
        // ConnStream should be small: Connection (16 bytes) + bool + Option<Bytes>.
        assert!(std::mem::size_of::<ConnStream>() <= 56);
    }
}
