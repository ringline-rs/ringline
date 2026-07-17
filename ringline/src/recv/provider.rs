//! Abstraction over the per-worker recv buffer strategy. Implementations:
//! classic size-class rings (`backend/uring/provided.rs`), INC ring
//! (`backend/uring/provided_inc.rs`), and the mio shared scratch. Keeps the
//! event loop from branching on kernel version / API inline.
//!
//! Consumed by later phases; unused for now.
#![allow(dead_code)]

use crate::recv::domain::RecvDomain;

/// A resolved recv completion: where the freshly-received bytes live and the
/// bookkeeping token needed to release/advance them. Semantics are per-impl:
/// classic returns a whole-buffer `bid`; INC returns `bid` + `offset`.
pub(crate) struct RecvView<'a> {
    pub data: &'a [u8],
    pub release: ReleaseToken,
}

#[derive(Clone, Copy)]
pub(crate) enum ReleaseToken {
    /// Classic provided buffer: replenish this whole bid when consumed.
    Bid(u16),
    /// INC buffer region: commit `len` consumed from `bid` at `offset`.
    IncRegion { bid: u16, offset: u32, len: u32 },
    /// mio scratch: nothing to release.
    None,
}

pub(crate) trait RecvBufferProvider {
    /// Arm (or re-arm) recv for `conn_index` in `domain`, sizing to
    /// `target_bytes`. Returns Err on submit failure (caller backpressures).
    fn arm(
        &mut self,
        conn_index: u32,
        domain: RecvDomain,
        target_bytes: usize,
    ) -> std::io::Result<()>;

    /// Release a consumed view back to the provider.
    fn release(&mut self, token: ReleaseToken);
}
