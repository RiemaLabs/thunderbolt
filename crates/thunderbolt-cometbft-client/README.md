# Thunderbolt CometBFT trust coordinator

`thunderbolt-cometbft-client` is the durable trust-state boundary around
`thunderbolt-cometbft`. It owns one operator-pinned light-client root and one
versioned roster of authenticated primary and witness identities. A caller
supplies transport and peer-authentication implementations; this crate ships no
network client, permissive authenticator, synthetic witness, or local rollback
checkpoint store.

For each execution height, the coordinator reads undecoded streaming trace
bodies under one monotonic deadline and applies the raw byte cap before JSON
decoding. Fetch and authentication return cancellable futures. The authenticator
must bind its real session evidence (for example, a pinned mTLS SPKI) to the
exact peer, request, and trace. Optional witnesses are fetched concurrently; the
first distinct authenticated subset satisfying `min_witnesses` is verified and
the exact subset is retained in the proof.
The coordinator invokes the CometBFT verifier once, then commits the complete
proof bundle, a receipt-derived summary, every request index, and the next trust
root in one SQLite transaction. SQLite is configured for WAL journaling and
`synchronous=FULL`. A commit error is treated as ambiguous: the live handle is
poisoned and must be reopened before the caller decides whether to retry.

Every SQLite mutation also produces an exact logical checkpoint chained to its
predecessor. The coordinator returns no new authority until a caller-supplied
`TrustCheckpointStore` in an independent trust domain wins the exact,
deadline-bound asynchronous CAS. A
normal open requires an exact match and therefore rejects stale or copied
databases. Explicit bootstrap, finality, rotation, and history recovery entry points can
finish only the latest one-step CAS and require the caller's durable intended
pin, roster, or canonical seal intent. Finality recovery additionally refetches,
reauthenticates, and reruns CometBFT verification from the externally anchored
prior root before comparing and promoting the exact candidate. Recovery never
promotes an arbitrary ahead file.

Historical queries by execution height or Ledger request digest are immutable.
They validate the stored bundle and its externally anchored checkpoint ancestry
but never fetch, authenticate, or advance the current trust root. The returned `FinalitySummary` deliberately
has no serialization implementation; its authority comes from this coordinator
after a local durable-record check, not from decoding an untrusted receipt. A
legal exact Ledger request replay retains the first finalized request location;
only a reuse with a different authenticated channel, participant, proposal, or
entry binding is a conflict.

There is no fixed update-count shutdown. Operators seal compact history epochs
regularly; a recommended cadence is 64 transitions, 64 MiB of aggregate proof
data, or 4,096 request mappings, whichever comes first. Configured absolute
maxima are 256 transitions, 256 MiB, and 65,536 requests. Preparation is an
explicit bounded synchronous operation for a daemon blocking worker. Its
canonical `HistorySealIntent` must be persisted independently before the SQLite
commit. The externally checkpointed manifest retains immutable full proof rows
and first-request locations while bounding normal restart and ancestry work.

Source rotation is a local operator action. It requires the exact current
configuration version, the next consecutive version, and a roster that still
fits the compositional proof budget. It never changes a trust root. SQLite paths
must be absolute and live in an owner-only Unix directory with safe canonical
ancestry; database and lock opens use no-follow semantics and retained inode
checks. Bootstrap validates all bounded inputs before touching the filesystem,
can retry a rolled-back initialization, and never repurposes a nonempty database.

Production deployment requires concrete authenticated transport,
peer-authenticator, and independent durable checkpoint-store implementations.
Operators must retain an independently reviewed bootstrap pin, stay within the
trusting period, and durably retain intended operations needed for explicit
ambiguous-write recovery. A local file, copied SQLite database, or ordinary RPC
success is not a trusted checkpoint implementation.
