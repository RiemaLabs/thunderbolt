# Bitcoin Thunderbolt operator runtime shell v2

`thunderbolt-runtime` is a fail-closed stepping stone between the committed
runtime configuration and future production Ledger, Holder, and Committee
services. It is not release completion and cannot make the current missing
cryptographic or external trust capabilities available.

Each `LedgerSupervisor`, `HolderSupervisor`, or `CommitteeSupervisor` consumes
the matching fresh `RuntimeHandoff`, retains it for the supervisor lifetime,
checks a mandatory role-typed handler against the exact runtime-manifest and
finality-verifier profiles plus the complete public deployment identity, and
holds an exclusive owner-only process lock inside the audited data directory.
There is no default handler, demo mode, accept-all verifier, or profile
downgrade.

The process lock contains the exact role, public deployment identity, runtime
and finality profiles, and a durable clean/running/dirty marker. An unclean
prior lifetime adds the immutable `dirty_restart_recovery_required` blocker and
remains sticky across an ordinary stop. A mismatched or malformed marker fails
construction. Clearing either condition requires a separate reviewed recovery
procedure; no runtime control method can clear it.

A dirty restart is a hard lifecycle gate, not only a readiness indication.
`Start` and `Drain` return a stable conflict without invoking the role handler.
Stopping an initialized dirty runtime releases the process lock without calling
the handler or rewriting the dirty marker.

Stopping any runtime whose handler never started invokes no handler hook. A
clean instance durably remains clean; a dirty instance durably remains dirty.
This makes an exact ambiguous `Stop` retry safe across process restart without
requiring the actor-lifetime RequestId ledger to survive the restart.

Liveness and readiness are independent. Liveness reports only whether the
bounded lifecycle actor is being polled. This stepping-stone version always
emits `NotReady`, even while the role handler is running. A future release must
add an explicit reviewed capability-attestation transition before it can emit
`Ready`; merely removing a blocker cannot enable readiness. This release also
carries the non-production profile blocker plus role-specific missing
capabilities.

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
the in-memory ledger but activates the hard dirty
gate, so no retry can reapply a hook before a future reviewed recovery path.

`RuntimeControl` implements the existing owner-only `ControlHandler` contract
but binds no Unix socket or other listener. It accepts only empty-payload
`runtime.status`, `runtime.redacted_config`, `runtime.blockers`,
`runtime.drain`, and `runtime.stop` methods. It exposes no start command, raw
protocol mutation, secret material, filesystem path, network endpoint, or
caller-provided time.
