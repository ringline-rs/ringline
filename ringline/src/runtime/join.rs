use std::future::Future;
use std::future::IntoFuture;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project_lite::pin_project! {
    /// Tracks whether a sub-future has completed, storing its output.
    #[project = MaybeDoneProj]
    pub enum MaybeDone<F: Future> {
        /// The future is still pending.
        Pending { #[pin] future: F },
        /// The future completed; output is stored here.
        Done { output: F::Output },
        /// The output was already taken.
        Gone,
    }
}

impl<F: Future> MaybeDone<F> {
    fn take_output(self: Pin<&mut Self>) -> Option<F::Output> {
        // Safety: we only move out of Done, which is !Unpin-safe since
        // the future field is never touched in Done/Gone states.
        unsafe {
            let this = self.get_unchecked_mut();
            match this {
                MaybeDone::Done { .. } => {
                    let MaybeDone::Done { output } = std::mem::replace(this, MaybeDone::Gone)
                    else {
                        unreachable!()
                    };
                    Some(output)
                }
                _ => None,
            }
        }
    }
}

impl<F: Future> Future for MaybeDone<F> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Poll the future if pending, collecting the output.
        let output = match self.as_mut().project() {
            MaybeDoneProj::Pending { future } => match future.poll(cx) {
                Poll::Ready(o) => o,
                Poll::Pending => return Poll::Pending,
            },
            MaybeDoneProj::Done { .. } | MaybeDoneProj::Gone { .. } => return Poll::Ready(()),
        };
        // The projected Pin<&mut F> from the match above is now dropped,
        // so we can safely overwrite the enum variant.
        // Safety: we are replacing Pending{future} with Done{output},
        // and the future is consumed by poll returning Ready.
        unsafe {
            let slot = Pin::into_inner_unchecked(self);
            *slot = MaybeDone::Done { output };
        }
        Poll::Ready(())
    }
}

/// Future that polls any number of sub-futures. See [`join_all`].
#[must_use = "futures do nothing unless awaited"]
pub struct JoinAll<F: Future> {
    children: Pin<Box<[MaybeDone<F>]>>,
    /// The most children left pending by one poll.
    limit: usize,
}

impl<F: Future> Future for JoinAll<F> {
    type Output = Vec<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let limit = self.limit;
        // Safety: the children are in a boxed slice and are never moved out of
        // it, so each stays pinned.
        let children = unsafe { self.children.as_mut().get_unchecked_mut() };
        let mut pending = 0;
        for child in children.iter_mut() {
            if pending == limit {
                return Poll::Pending;
            }
            // Safety: as above.
            if unsafe { Pin::new_unchecked(child) }.poll(cx).is_pending() {
                pending += 1;
            }
        }
        if pending > 0 {
            return Poll::Pending;
        }
        Poll::Ready(
            children
                .iter_mut()
                .map(|child| {
                    // Safety: as above.
                    unsafe { Pin::new_unchecked(child) }
                        .take_output()
                        .expect("JoinAll polled after Ready")
                })
                .collect(),
        )
    }
}

/// Poll any number of futures concurrently, returning their outputs in order
/// when all have completed.
///
/// Each wake of the task polls every child that is not done, so N children cost
/// N polls per wake. Use it for a bounded fan-out, not for a set that lives as
/// long as the task. To start only some at a time, for example because each
/// takes a send pool slot, use [`join_all_limited`].
pub fn join_all<I>(futures: I) -> JoinAll<<I::Item as IntoFuture>::IntoFuture>
where
    I: IntoIterator,
    I::Item: IntoFuture,
{
    join_all_limited(futures, usize::MAX)
}

/// [`join_all`], with at most `limit` futures started and not finished at a
/// time. The first `limit` start at once, and each later one starts when an
/// earlier one finishes.
///
/// # Panics
///
/// Panics if `limit` is 0.
pub fn join_all_limited<I>(futures: I, limit: usize) -> JoinAll<<I::Item as IntoFuture>::IntoFuture>
where
    I: IntoIterator,
    I::Item: IntoFuture,
{
    assert!(limit > 0, "join_all_limited limit must be > 0");
    let children: Box<[_]> = futures
        .into_iter()
        .map(|future| MaybeDone::Pending {
            future: future.into_future(),
        })
        .collect();
    JoinAll {
        children: children.into(),
        limit,
    }
}

pin_project_lite::pin_project! {
    /// Future that polls two sub-futures and returns both outputs when complete.
    pub struct Join<A: Future, B: Future> {
        #[pin] a: MaybeDone<A>,
        #[pin] b: MaybeDone<B>,
    }
}

impl<A: Future, B: Future> Future for Join<A, B> {
    type Output = (A::Output, B::Output);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let a_done = this.a.as_mut().poll(cx).is_ready();
        let b_done = this.b.as_mut().poll(cx).is_ready();
        if a_done && b_done {
            let a_out = this.a.take_output().unwrap();
            let b_out = this.b.take_output().unwrap();
            Poll::Ready((a_out, b_out))
        } else {
            Poll::Pending
        }
    }
}

/// Poll two futures concurrently, returning both outputs when they complete.
///
/// Unlike [`select()`](crate::select) which returns whichever finishes first,
/// `join` waits for **both** futures. Useful for fan-out patterns like parallel
/// backend requests.
///
/// The futures are polled in order (a, then b) on each iteration.
pub fn join<A: IntoFuture, B: IntoFuture>(a: A, b: B) -> Join<A::IntoFuture, B::IntoFuture> {
    Join {
        a: MaybeDone::Pending {
            future: a.into_future(),
        },
        b: MaybeDone::Pending {
            future: b.into_future(),
        },
    }
}

pin_project_lite::pin_project! {
    /// Future that polls three sub-futures and returns all outputs when complete.
    pub struct Join3<A: Future, B: Future, C: Future> {
        #[pin] a: MaybeDone<A>,
        #[pin] b: MaybeDone<B>,
        #[pin] c: MaybeDone<C>,
    }
}

impl<A: Future, B: Future, C: Future> Future for Join3<A, B, C> {
    type Output = (A::Output, B::Output, C::Output);

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        let a_done = this.a.as_mut().poll(cx).is_ready();
        let b_done = this.b.as_mut().poll(cx).is_ready();
        let c_done = this.c.as_mut().poll(cx).is_ready();
        if a_done && b_done && c_done {
            let a_out = this.a.take_output().unwrap();
            let b_out = this.b.take_output().unwrap();
            let c_out = this.c.take_output().unwrap();
            Poll::Ready((a_out, b_out, c_out))
        } else {
            Poll::Pending
        }
    }
}

/// Poll three futures concurrently, returning all outputs when they complete.
///
/// Waits for **all three** futures. Useful for fan-out patterns with three
/// concurrent operations (e.g., three parallel backend requests).
pub fn join3<A: IntoFuture, B: IntoFuture, C: IntoFuture>(
    a: A,
    b: B,
    c: C,
) -> Join3<A::IntoFuture, B::IntoFuture, C::IntoFuture> {
    Join3 {
        a: MaybeDone::Pending {
            future: a.into_future(),
        },
        b: MaybeDone::Pending {
            future: b.into_future(),
        },
        c: MaybeDone::Pending {
            future: c.into_future(),
        },
    }
}
