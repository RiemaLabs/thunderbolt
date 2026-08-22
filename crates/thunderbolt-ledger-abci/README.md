# Thunderbolt Ledger ABCI

`thunderbolt-ledger-abci` is the CometBFT v0.38.25 ABCI 2.0 execution adapter
for the standalone Bitcoin Thunderbolt version 2 Ledger application. It uses
`tendermint-abci` and `tendermint-proto` 0.40.4 and reports application version
`2` from `Info` and `InitChain`.

Transactions are canonical JSON encodings of `SignedProposalV2`. `CheckTx`
performs bounded chain, signature, and durable request-conflict checks, then
calls a required time-independent static proof verifier. Permanent rejections
are cached by logical `(channel, participant, request, entry)` identity, not by
signature bytes. New duplicates and exact durable replays return nonzero on
both New and Recheck; clients use request-status queries for idempotency.
`PrepareProposal` preserves relative order while enforcing both CometBFT's
requested byte limit and Thunderbolt's hard scan/byte limits, charging malformed
and duplicate candidates too. It greedily runs the exact
rollback-only preview after each candidate, skips a transaction that would make
the block invalid, and caps cumulative preview work at 4,096 proposal entries.
This prevents an admitted bad proof from poisoning every proposal round while
keeping proposer work bounded. `ProcessProposal` repeats full deterministic
validation through that same path.

`FinalizeBlock` repeats that rollback-only execution and keeps an opaque
`PreparedBlockV2` in shared memory. It does not advance SQLite. `Commit`
re-executes the prepared block, compares the exact block, application hash, and
disposition counts, and atomically persists it. A crash before `Commit` leaves
the old durable height for the CometBFT handshake to replay. A lost response
after `Commit` is recovered through `Info`, and exact block replay is
idempotent.

Every `Commit` without an in-memory prepared block fails closed. After a
restart, CometBFT must use `Info` and replay `FinalizeBlock` before `Commit`;
the live crash gate exercises that handshake. The `Application` implementation
also requires a non-returning `FatalAbciHandler`. Storage, Info, Finalize, and
pre/post-Commit ambiguity close the supervised session or terminate the process
before an ordinary success response can escape.

`ConsensusProfileV2` is mechanically derived from the installed verifier's
identity and deployment descriptor, the exact chain, reducer limits, and ABCI
resource policy. Its digest is stored in SQLite and must match canonical genesis
`app_state`, preventing replicas with different proof policy from joining.

The application hash returned while executing height `H` is the state placed in
the header at height `H + 1`. `Commit` does not return an application hash under
ABCI 2.0.

The adapter supports bounded `status`, `block`, `channel`, `request`, and
execution-proof query paths. The proof response is deterministic execution
evidence only and returns no CometBFT `ProofOps` or finality capability. A
request setting ABCI's `prove` flag is rejected even on the execution-proof
path. State-sync snapshots fail closed. With vote extensions disabled,
verification accepts only the required empty extension and rejects nonempty
values. The adapter does not run
CometBFT, configure validator governance, verify quorum finality, provide a
network daemon, or claim Byzantine finality by itself.

Hard application limits are 1 MiB per transaction, 24 MiB of transaction bytes
per block, 1,024 transactions per block, 4,096 scanned proposer candidates,
32 MiB of scanned proposer bytes, 128 query-key bytes, and 24 MiB per query
value. Query JSON is written through a bounded writer. Operators must set
CometBFT's consensus block limit within those bounds. The upstream
`tendermint-abci` socket codec does not cap a length-delimited frame before
allocation, so a production process must use a reviewed bounded dispatcher and
authenticated local boundary. The feature-gated live process includes a
26 MiB pre-allocation cap on a loopback-only listener, but is not a production
server.

## Opt-in live gate

The `insecure-live-test` feature builds a dedicated test process whose external
proof verifier accepts everything. Cargo does not build that binary or its live
test by default. It must never be enabled in a release deployment.

Run the isolated gate explicitly:

```sh
THUNDERBOLT_COMETBFT_LIVE=1 cargo test -p thunderbolt-ledger-abci \
  --features insecure-live-test --test live_cometbft -- --ignored --nocapture
```

The harness pins CometBFT v0.38.25's signed tag object, commit, signer
fingerprint, and official source-archive SHA-256. It builds that source in a
temporary cache, runs four validators against four independent application
databases on random loopback ports, injects a crash after `FinalizeBlock` and
before `Commit`, restarts validator and application processes, checks replica
hashes and the `H` to `H + 1` binding, rejects an invalid transaction, and
removes every process and temporary file. This is compatibility and recovery
evidence only. Empty blocks do not exercise production Open, Invoice, Transfer,
or Finalize proof verification.
