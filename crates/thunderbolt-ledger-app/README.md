# Thunderbolt Ledger application

`thunderbolt-ledger-app` is the crash-safe SQLite application layer for the
Bitcoin Thunderbolt Ledger contract. It combines:

- BIP340-authenticated `SignedProposalV2` values from `thunderbolt-ledger`;
- deterministic block metadata, application hashes, and Merkle proofs;
- the concurrent-Invoice state machine in `thunderbolt-protocol::v2`; and
- one atomic SQLite transaction for block, request, Invoice-history, and
  channel-state persistence.

Consensus supplies the Ledger chain ID, positive height, positive Unix block
time in milliseconds, prior application hash, and proposal order. The
application never reads a local clock. It verifies exact chain, height,
application-hash, and monotonic-time continuity before execution.

Consensus deployments must set `ApplicationOptions.consensus_profile_digest`.
The schema stores that immutable 32-byte value alongside the chain ID and
reducer limits and rejects a reopen under a different verifier/deployment
profile. An unprofiled database can bind a profile only while its durable head
is still empty; an executed unprofiled database cannot be assigned a new proof
policy.

The ABCI adapter reports the application version defined by this contract.
Execution at consensus height `H` returns the
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

`preview_block` runs that same request-reservation, verification, reduction,
and storage path inside a rollback-only SQLite transaction. The resulting
opaque `PreparedBlockV2` can be passed to `commit_prepared_block`, which
re-executes the block and commits only after the executed block, application
hash, and disposition counts match the preview. This is the intended
`FinalizeBlock`/`Commit` boundary for an ABCI adapter; previewing never advances
the durable application head.

Schema version 3 adds a covering, non-unique
`(channel_context_id, entry_hash, height, block_index)` index. Non-uniqueness is
intentional because an exact signed request may be executed again as a replay.
`first_entry_location_through` always returns the earliest matching position at
or before a caller-selected execution checkpoint, and verifies the checkpoint
app hash, index row, pointed block, channel, and entry in one SQLite read
transaction. This makes an earlier `None` meaningful only for that exact
checkpoint; it cannot be reused as a later absence claim.

`block_range` returns an exact positive count of globally contiguous whole
`ExecutedBlockV2` values. Empty consensus blocks remain explicit elements and
pages never split a block. The cursor binds the chain, first height, and exact
predecessor app hash. SQLite blob lengths and the complete JSON-array byte
budget are checked before response blobs are decoded, then every accepted
block is canonically decoded and successor-validated. Range reads are limited
to 64 blocks and 23 MiB of canonical block-array bytes. They fail rather than
returning an empty or provider-truncated page.

`thunderbolt-ledger-abci` exposes this application to CometBFT, and
`thunderbolt-ledger-comet-client` verifies finality before returning finalized
entries. This crate handles deterministic execution and storage.
