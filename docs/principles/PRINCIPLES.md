# Ringline Design Principles

Ringline is a library, not a service. It runs inside someone else's process, on
their threads, under their workload, and it is judged on whether the program
built with it behaves predictably. That framing decides what belongs here:
principles about the construction of the runtime and its protocol crates, not
about the operation of the systems built on top of them.

These are stances, not rules. They exist to make disagreement precise — a change
that departs from one of them is not forbidden, but it should say which
principle it departs from and why the trade is worth it.

---

## 1. The kernel contract is the correctness boundary

Memory handed to the kernel must outlive the operation, not the call. A
submission returns immediately; the kernel reads the referenced memory at a time
of its choosing, and for zero-copy transmission it may hold that reference until
a second, later notification. Ownership therefore ends when the kernel says so,
never when the submitting function returns.

The same asymmetry governs completions. Slots are reused, so a completion may
describe an occupant that no longer exists. Every completion is validated
against the generation of the slot it names before it is allowed to touch state.

These are not defensive habits. They are the terms on which the interface is
offered, and code that violates them is incorrect even when it appears to work.

## 2. Bind early, run fixed

Variability is resolved as early as it can be: at compile time in preference to
launch time, at launch time in preference to per-request. A backend is selected
when the binary is built. Configuration is validated once, at construction, and
is immutable thereafter.

The benefit is not speed in isolation but predictability. What is fixed early is
the *envelope*: which shapes the runtime can take, and what bounds them. Buffers
may still grow within a configured ceiling, and a threshold may still steer a
request down one of two known paths. What is excluded is the runtime deciding
for itself to occupy a shape nobody declared, so that an operator meets a
regime at hour six that was not visible at hour one.

This forecloses genuine flexibility, and that cost is accepted deliberately.
Where adaptation is genuinely needed, it belongs in an explicit, observable loop
rather than in implicit runtime polymorphism.

## 3. Partition rather than share

Mutable state belongs to one thread. Work is not migrated between threads, and
where two threads would otherwise contend for a resource, each is given its own.

Sharing that is written is expensive to reason about: it converts a local
question about one thread's behaviour into a global question about all of them,
and it does so exactly at the load where the answer matters. Duplication is the
price paid for keeping the question local.

Sharing that is only read is a different matter, and the distinction is worth
keeping. A flag that every worker consults and almost nobody writes costs a
cache line that stays valid; partitioning it would buy nothing. So the rule is
not that nothing is shared — it is that anything shared and written is
deliberate, and that contention is demonstrated before duplication is paid for.

## 4. Account for copies and syscalls

The cost of the hot path is counted, not estimated. For any path that carries
payload, it should be possible to state how many times a byte is copied between
arriving from the network and reaching the caller, and why each copy is
necessary.

This is a design discipline before it is an optimisation one. Knowing that a
receive path costs exactly one copy, and where, makes it obvious which changes
can possibly help and which are rearranging cost rather than removing it.

Where a copy cannot be removed, it is documented rather than quietly tolerated,
so the next person does not have to rediscover why it is there.

## 5. Symmetry is the default; asymmetry is presumed defect

Where two things ought to behave the same, they do, and a difference between
them is treated as a bug until someone explains it.

This applies in several directions. Two backends implementing one interface
should agree on observable behaviour, differing only where the underlying
mechanism genuinely differs — and those differences are stated, not discovered.
A decoder that enforces a limit implies an encoder that refuses to produce what
the decoder would reject. A fallible operation on one type implies the same
operation is fallible on its sibling.

Asymmetry is where defects hide, because each half looks reasonable alone. The
discipline is to compare the halves deliberately rather than to read them in
isolation.

## 6. Untrusted input meets checked arithmetic

Any value that arrives from the wire, or through a public field a caller can
set, is untrusted. Arithmetic on such values is checked, saturating, or
otherwise explicit about what happens at the boundary.

Unchecked arithmetic on untrusted input has a particularly bad failure mode: it
panics in development, where it is noticed and dismissed as an edge case, and
wraps silently in release, where it is not noticed at all. A wrapped length
becomes a wrong slice, an inverted limit, or a frame boundary in the wrong
place — and none of those announce themselves.

The check is not the interesting part. Deciding what the boundary *means* is:
whether exceeding it is a protocol error, a saturation, or a caller mistake, and
saying so in the signature.

## 7. "Incomplete" is a promise

A parser that reports it needs more data is promising that more data can help.
If no additional bytes could ever satisfy the condition, reporting incompleteness
strands the caller: it keeps reading, keeps buffering, and never learns that it
is waiting for something that will not come.

So a decision to wait must be reachable only when waiting can succeed.
Inconsistency that is already visible is an error now, not an error later.
Growth that cannot terminate is bounded, so that an unterminated input fails
rather than consumes.

The general form: every state that defers a decision must have a path out of
itself.

## 8. Measured, or it is not a claim

Statements about performance are backed by measurement against a stated
baseline, on hardware and a workload that resemble the target. An argument from
mechanism is a hypothesis; it earns the status of a claim only when something
has been run.

This cuts in both directions, and the second is the one usually skipped: a
measurement showing that a promising change does nothing has settled the
question as firmly as one showing a win, and is worth the same effort to record.
Without that, the same idea is re-proposed indefinitely.

Beware the environment before blaming the code. Link capacity, interrupt
placement, and processor topology have all produced results that looked like
regressions and were not.

## 9. The public surface is a contract

What is exposed is chosen, not defaulted. Fields are private and reached through
methods; construction goes through validated builders; error enumerations are
extensible so that adding a variant is not a breaking change.

A public field is a permanent commitment to a representation. A method is a
commitment only to a question and an answer, which leaves room to change how the
answer is produced.

Breaking changes are batched into deliberate releases rather than released
individually as they arise, so that a consumer pays the upgrade cost on a
schedule they can plan for.

## 10. An obligation the caller must keep is declared in the signature

Principle 1 concerns what this library owes the kernel. This one concerns what
it hands back to the people using it.

Where an operation is only correct if the caller does something — keeps a buffer
alive past the call, aligns it, guarantees it is not aliased — that requirement
belongs in the signature, as an `unsafe fn` with the obligation written down. It
does not belong hidden behind a safe wrapper that cannot actually uphold it.

A safe signature is a promise that no use of it can cause undefined behaviour.
Applying one to an operation whose safety depends on the caller does not make
the obligation go away; it makes it invisible, and moves the eventual failure
somewhere far from the code responsible for it. The discomfort of an `unsafe`
keyword at the call site is the mechanism working.

The same reasoning applies to panics. An operation that will abort on some
inputs says so, and a caller who cannot guarantee those inputs is given a
fallible variant instead of being left to discover the panic in production.

---

These principles are revisable. When one of them is repeatedly inconvenient in
the same way, that is evidence about the principle, not only about the code.
