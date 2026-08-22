# Thunderbolt Ledger ABCI

`thunderbolt-ledger-abci` is the CometBFT v0.38.25 ABCI 2.0 execution adapter
for the standalone Bitcoin Thunderbolt version 2 Ledger application. It uses
`tendermint-abci` and `tendermint-proto` 0.40.4 and reports application version
`2` from `Info` and `InitChain`.

Transactions are canonical JSON encodings of `SignedProposalV2`. `CheckTx`
performs bounded chain, signature, and durable request-conflict checks.
`PrepareProposal` preserves relative order while enforcing both CometBFT's
requested byte limit and Thunderbolt's hard limits. `ProcessProposal` runs full
deterministic validation through the exact rollback-only application path.

`FinalizeBlock` repeats that rollback-only execution and keeps an opaque
`PreparedBlockV2` in shared memory. It does not advance SQLite. `Commit`
re-executes the prepared block, compares the exact block, application hash, and
disposition counts, and atomically persists it. A crash before `Commit` leaves
the old durable height for the CometBFT handshake to replay. A lost response
after `Commit` is recovered through `Info`, and exact block replay is
idempotent.

The application hash returned while executing height `H` is the state placed in
the header at height `H + 1`. `Commit` does not return an application hash under
ABCI 2.0.

The adapter supports bounded `status`, `block`, `channel`, `request`, and
execution-proof query paths. The proof response is deterministic execution
evidence only and returns no CometBFT `ProofOps` or finality capability.
State-sync snapshots and vote extensions fail closed. The adapter does not run
CometBFT, configure validator governance, verify quorum finality, provide a
network daemon, or claim Byzantine finality by itself.

Hard application limits are 1 MiB per transaction, 24 MiB of transaction bytes
per block, 1,024 transactions per block, 128 query-key bytes, and 24 MiB per
query value. Operators must set CometBFT's consensus block limit within those
bounds and protect the local ABCI socket. The upstream `tendermint-abci` socket
codec does not itself impose a total length-delimited frame cap before protobuf
decoding, so a deployment still needs a trusted loopback/Unix boundary or a
separately reviewed frame-limiting proxy.
