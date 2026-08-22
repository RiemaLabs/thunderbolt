# Thunderbolt Floor ABCI

`thunderbolt-floor-abci` is the CometBFT v0.38 ABCI 2.0 execution adapter for
the independent signed Bitcoin Thunderbolt rollback floor. Application and
transaction codec versions are fixed at 2.

## Consensus profile

The adapter derives one profile digest from the exact Floor chain, ordered
Ed25519 validator genesis, application/codec versions, and every transaction,
block, proposer-scan, query, vote, and frame bound. `FloorGenesis` must be
constructed with that digest. `InitChain` then requires the exact chain,
validator list, canonical app-state bytes, 1 MiB Comet block limit, unlimited
gas policy, application version 2, Ed25519 validator policy, and disabled vote
extensions. `Info` rechecks the durable Floor profile before reporting its
head.

The adapter never emits validator updates and provides no validator rotation or
governance mechanism.

## Signed transaction format

Transactions use a canonical fixed binary codec, not JSON. The maximum is 496
bytes and includes the full Floor chain and vault identity, exact CAS
checkpoints, x-only operator key, nonzero audit nonce, target height, expected
prior app hash, and BIP340 signature. Decode checks the outer bound before any
allocation, allocates only the at-most-128-byte chain ID, reconstructs typed
Floor values, verifies BIP340, and requires byte-for-byte canonical re-encoding.

`CheckTx` admits at most one logical identity for one exact next head; only an
exact cached `Recheck` is accepted. Its rollback-only preview uses the
last-committed deterministic time for contextual admission. That synthetic
time is never returned as execution evidence.

`PrepareProposal` preserves relative order, deduplicates identities and request
digests, scans at most 4,096 transactions/approximately 2 MiB including rejected
values, and uses a rotating in-memory cursor so a large same-identity prefix
cannot permanently hide later identities. Every selected prefix passes the
exact cumulative rollback preview. Operators still need bounded CometBFT
mempool count/bytes, connection rate limits, and fee policy.

## Finalize and Commit

`CheckTx`, `PrepareProposal`, `ProcessProposal`, and `FinalizeBlock` are
rollback-only. `FinalizeBlock` stages the exact prepared block in shared memory;
only `Commit` may durably mutate SQLite. Commit re-executes and compares the
exact block, result set, and application hash.

A crash before Commit leaves the durable head unchanged, so CometBFT replays
Finalize/Commit after the Info handshake. If Commit may have landed but the
acknowledgement is lost, the non-returning fatal handler terminates the session
or process; cold Info reports the durable height. Missing stage, storage error,
poison, mismatch, and ambiguity never produce an ordinary successful ABCI
response. Every callback converts storage/corruption/poison failures into that
same non-returning boundary.

## Queries and disabled surfaces

Bounded status, current-checkpoint, committed-block, result-proof, and
state-proof queries are available. Every response is explicitly labeled
`execution_only=true` and `consensus_finality=false`; ABCI `prove=true` is
rejected and no `ProofOps` are returned. Local history-compaction anchors and
anchor-state proofs are deliberately absent because validator-local retention
is not consensus state.

Snapshots return empty/abort. Vote extensions are disabled and only an empty
extension is accepted. Mainnet identities remain disabled by the Floor genesis.

This crate does not start CometBFT, provide validator governance, authenticate
network transport, verify quorum finality, or expose a local finality shortcut.
The upstream `tendermint-abci` socket codec does not enforce the exported frame
bound before allocation; production deployment requires a reviewed bounded
dispatcher on an authenticated local boundary. A four-validator live CometBFT
gate remains separate from this transport-neutral adapter package.
