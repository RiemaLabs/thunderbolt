# Bitcoin Thunderbolt operator runtime

`thunderbolt-runtime` provides the role-aware lifecycle supervisor used by
Ledger, Holder, and Committee processes. Each supervisor consumes the matching
fresh `RuntimeHandoff`, retains it for its lifetime, validates the role handler
against the runtime-manifest and finality profiles plus the public deployment
identity, and holds an exclusive owner-only process lock in the data directory.

The process lock contains the exact role, public deployment identity, runtime
and finality profiles, and a durable clean/running/dirty marker. An unclean
prior lifetime adds the immutable `dirty_restart_recovery_required` blocker and
remains sticky across an ordinary stop. A mismatched or malformed marker fails
construction. Clearing either condition requires a separate recovery procedure;
no runtime control method can clear it.

A dirty restart is a hard lifecycle gate, not only a readiness indication.
`Start` and `Drain` return a stable conflict without invoking the role handler.
Stopping an initialized dirty runtime releases the process lock without calling
the handler or rewriting the dirty marker.

Stopping any runtime whose handler never started invokes no handler hook. A
clean instance durably remains clean; a dirty instance durably remains dirty.
This makes an exact ambiguous `Stop` retry safe across process restart without
requiring the actor-lifetime RequestId ledger to survive the restart.

Liveness and readiness are independent. Liveness reports only whether the
bounded lifecycle actor is being polled. Version 1.0 leaves the
capability-attestation transition to the role integration, so the base
supervisor reports `NotReady` until that integration supplies it.

The caller continuously polls `RuntimeSupervisor::run`. Fixed `Start`, `Drain`,
and `Stop` hooks execute serially through an eight-command mailbox under
configuration-derived deadlines and supervisor-owned cancellation tokens. A
handler error, panic, timeout, dropped actor future, or durable marker failure
faults the runtime and never becomes a successful response. Handler error text
is discarded.

Lifecycle mutations carry the control plane's exact `RequestId`. A non-evicting
64-entry actor-lifetime ledger binds each ID to one event and its exact result
and status, including after `Stop`. Same-ID retries replay; a changed event
conflicts; new IDs fail closed when the ledger is full. Dropping or timing out a
caller cancels the in-flight hook, restores the prior state, and leaves that ID
retryable. If hook completion and caller cancellation become ready together,
completion wins and the result is cached before any replay. A crash discards
the in-memory ledger but activates the hard dirty gate, so no retry can reapply
a hook before an explicit recovery path.

`RuntimeControl` implements the owner-only `ControlHandler` contract, which
`thunderboltd` exposes through a local Unix socket. It accepts the
`runtime.status`, `runtime.redacted_config`, `runtime.blockers`,
`runtime.drain`, and `runtime.stop` methods with empty payloads. It does not
expose protocol mutations or secret material.
