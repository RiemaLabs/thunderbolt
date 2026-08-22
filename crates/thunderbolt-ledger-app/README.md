# Thunderbolt Ledger application

`thunderbolt-ledger-app` is the crash-safe SQLite application layer for the
standalone Bitcoin Thunderbolt version 2 contracts. It combines:

- BIP340-authenticated `SignedProposalV2` values from `thunderbolt-ledger`;
- deterministic block metadata, application hashes, and Merkle proofs;
- the concurrent-Invoice state machine in `thunderbolt-protocol::v2`; and
- one atomic SQLite transaction for block, request, Invoice-history, and
  channel-state persistence.

Consensus supplies the Ledger chain ID, positive height, positive Unix block
time in milliseconds, prior application hash, and proposal order. The
application never reads a local clock. It verifies exact chain, height,
application-hash, and monotonic-time continuity before execution.

The application version is `2`. A future ABCI `Info` and `InitChain` boundary
must report that exact value. Execution at consensus height `H` returns the
application hash committed by the CometBFT header at height `H + 1`; the hash
is never relabeled as belonging to the next executed application block.

The request index is keyed by stable channel context, actor-derived participant
ID, and actor-scoped request digest. A new mapping is inserted inside the
writer transaction before signature and external proof verification. Exact
retries replay without proof verification. Conflicting reuse fails before the
expensive verifier runs.

`LedgerApplicationVerifierV2` is a marker over the protocol's deterministic
`ExternalVerifierV2` hooks. Clients cannot submit verification evidence. A
rejection or any later error rolls back the complete block transaction.

This crate is not a network, consensus engine, ABCI server, finality verifier,
wallet, or role runtime. `ExecutedBlockV2`, its application hash, and its Merkle
proofs establish deterministic execution only. A future consensus integration
must verify finality separately before exposing a finality capability.
