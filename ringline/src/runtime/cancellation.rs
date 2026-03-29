//! Structured cancellation via [`CancellationToken`].
//!
//! Tokens can be shared across tasks on the same worker thread (they are
//! `Clone` but `!Send`). A parent token can create child tokens that are
//! automatically cancelled when the parent is cancelled.
//!
//! # Example
//!
//! ```rust,no_run
//! use ringline::CancellationToken;
//!
//! # async fn example(conn: ringline::ConnCtx) {
//! let token = CancellationToken::new();
//! let child = token.child_token();
//!
//! ringline::spawn(async move {
//!     // This resolves when the token is cancelled.
//!     child.cancelled().await;
//! }).unwrap();
//!
//! // Cancel — wakes all tasks awaiting this token or any child.
//! token.cancel();
//! # }
//! ```

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use super::CURRENT_TASK_ID;
use super::io::try_with_state;

/// Shared state for a cancellation token.
struct State {
    cancelled: bool,
    /// Task IDs waiting for cancellation. Supports multiple waiters
    /// (e.g. several tasks each calling `cancelled()` on clones of the
    /// same token).
    waiters: Vec<u32>,
    /// Child tokens to cancel when this token is cancelled.
    children: Vec<Rc<RefCell<State>>>,
}

/// A token for cooperative cancellation of async tasks.
///
/// Clone the token to share it across tasks on the same worker.
/// Call [`cancel()`](Self::cancel) to signal cancellation and wake all
/// tasks awaiting [`cancelled()`](Self::cancelled).
///
/// Tokens form a tree: [`child_token()`](Self::child_token) creates a
/// child that is automatically cancelled when the parent is.
pub struct CancellationToken {
    state: Rc<RefCell<State>>,
}

impl CancellationToken {
    /// Create a new cancellation token.
    pub fn new() -> Self {
        CancellationToken {
            state: Rc::new(RefCell::new(State {
                cancelled: false,
                waiters: Vec::new(),
                children: Vec::new(),
            })),
        }
    }

    /// Cancel the token and all child tokens.
    ///
    /// All tasks awaiting [`cancelled()`](Self::cancelled) on this token
    /// or any descendant are woken.
    pub fn cancel(&self) {
        cancel_state(&self.state);
    }

    /// Returns `true` if the token has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.state.borrow().cancelled
    }

    /// Returns a future that completes when the token is cancelled.
    ///
    /// If the token is already cancelled, the future resolves immediately.
    pub fn cancelled(&self) -> CancelledFuture {
        CancelledFuture {
            state: Rc::clone(&self.state),
        }
    }

    /// Create a child token that is cancelled when this token is cancelled.
    ///
    /// The child can also be cancelled independently without affecting the
    /// parent.
    pub fn child_token(&self) -> CancellationToken {
        let child = CancellationToken::new();
        let mut s = self.state.borrow_mut();
        if s.cancelled {
            // Parent already cancelled — cancel the child immediately.
            drop(s);
            child.cancel();
        } else {
            s.children.push(Rc::clone(&child.state));
        }
        child
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for CancellationToken {
    fn clone(&self) -> Self {
        CancellationToken {
            state: Rc::clone(&self.state),
        }
    }
}

/// Recursively cancel a state and all its children, waking all waiters.
fn cancel_state(state: &Rc<RefCell<State>>) {
    let (waiters, children) = {
        let mut s = state.borrow_mut();
        if s.cancelled {
            return;
        }
        s.cancelled = true;
        let waiters = std::mem::take(&mut s.waiters);
        let children = std::mem::take(&mut s.children);
        (waiters, children)
    };

    // Wake all waiters. Drop the borrow before calling try_with_state.
    for waiter_id in waiters {
        try_with_state(|_driver, executor| {
            executor.wake_task(waiter_id);
        });
    }

    // Recursively cancel children.
    for child in children {
        cancel_state(&child);
    }
}

/// Future returned by [`CancellationToken::cancelled`].
///
/// Resolves when the associated token is cancelled.
pub struct CancelledFuture {
    state: Rc<RefCell<State>>,
}

impl Future for CancelledFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        let mut s = self.state.borrow_mut();
        if s.cancelled {
            return Poll::Ready(());
        }
        let task_id = CURRENT_TASK_ID.with(|c| c.get());
        if !s.waiters.contains(&task_id) {
            s.waiters.push(task_id);
        }
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_token_is_not_cancelled() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancel_sets_flag() {
        let token = CancellationToken::new();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let token = CancellationToken::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn clone_shares_state() {
        let token = CancellationToken::new();
        let clone = token.clone();
        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn child_cancelled_with_parent() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[test]
    fn child_cancelled_independently() {
        let parent = CancellationToken::new();
        let child = parent.child_token();
        child.cancel();
        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled());
    }

    #[test]
    fn child_of_cancelled_parent_is_cancelled() {
        let parent = CancellationToken::new();
        parent.cancel();
        let child = parent.child_token();
        assert!(child.is_cancelled());
    }

    #[test]
    fn grandchild_cancelled_with_grandparent() {
        let gp = CancellationToken::new();
        let parent = gp.child_token();
        let child = parent.child_token();
        gp.cancel();
        assert!(parent.is_cancelled());
        assert!(child.is_cancelled());
    }

    #[test]
    fn default_is_new() {
        let token = CancellationToken::default();
        assert!(!token.is_cancelled());
    }
}
