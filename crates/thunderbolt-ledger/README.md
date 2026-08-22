# Thunderbolt Ledger contract

`thunderbolt-ledger` defines the deterministic application contract executed by
`thunderbolt-ledger-app` and exposed to CometBFT through
`thunderbolt-ledger-abci`.

## What is signed

An actor submits a `SignedProposalV2` containing:

- a consensus `ledger_chain_id` and complete stable `ChannelBindingV2`;
- the per-channel sequence and prior entry hash;
- a request nonce whose request digest is derived from the Ledger chain,
  channel, actor key, and role;
- the explicit `bip340_v1` key algorithm, x-only actor key, and role;
- an event kind and non-empty canonical event bytes, bounded at 2 MiB minus a
  2 KiB transport reserve.

The participant id is derived from the validated BIP340 key. It is never
accepted as a caller-supplied name. The signature covers a domain-separated
binary transcript in which every label and value is length-prefixed. Serde and
JSON representations are not signing formats.

Compact signed-proposal and Ledger-RPC request bodies share a 4 MiB ceiling.
Because canonical event bytes render as hexadecimal in JSON, the event limit
reserves 4 KiB for maximum chain, binding, request, actor, signature, and RPC
metadata. Boundary tests construct the maximum-field form and reject one byte
over the event and transport limits.

`SignedProposalV2::verified_view` gives a reducer a signature-free capability
containing only authenticated typed fields and the exact entry hash. Raw
verifier evidence, witnesses, decrypted shares, and private protocol state are
outside this contract.

## Block execution commitment

The consensus layer supplies a positive height, a positive block time in Unix
milliseconds, a prior application hash, and proposal order. No local clock is
read. The block time is recorded in each executed-entry metadata record and
is available to deterministic event verification, including invoice expiry.

The ordered Merkle tree uses separate empty, leaf, and internal-node domains.
Leaves bind the Ledger chain id, height, consensus block time, entry index, and
entry hash. The recursive tree splits at the largest power of two below the
leaf count, so order is unambiguous and no final leaf is duplicated.

The application hash advances as:

```text
SHA256(
  domain,
  ledger_chain_id,
  previous_app_hash,
  block_height,
  block_time_ms,
  entry_count,
  entry_merkle_root
)
```

Every labeled item is length-prefixed. Empty blocks have a defined Merkle root
and still advance the application hash. A block accepts at most 1,024 entries
and 8 MiB of total canonical event bytes.

`ExecutedBlockV2` is deliberately named for what it proves: deterministic,
self-consistent application execution. It is not proof that validators reached
consensus. `validate_successor` checks the same Ledger chain, exact next height,
prior application hash, and monotonic block time against a trusted previous
execution. Ordered inclusion proofs authenticate entry metadata to an executed
block's Merkle root.

`ExecutedBlockCommitmentV2` is the compact form for role evidence. It contains
the exact chain, height, consensus time, previous application hash, entry count,
ordered Merkle root, and application hash, but no executed-entry vector. Decode
and construction recompute the application hash. `EntryMerkleProofV2` can verify
either exact metadata or a recomputed `ExecutedEntryV2` against this commitment,
while the existing full-block verification API remains available.

`thunderbolt-cometbft` verifies the validator quorum or light-client chain, and
`thunderbolt-ledger-comet-client` binds finality evidence to the exact execution
commitment before returning finalized entries.

## Integration

`thunderbolt-ledger-app` checks the configured chain, persistent channel head,
request-digest mapping, block continuity, and canonical event schema before it
runs the protocol reducer and stores an executed block atomically.
`thunderbolt-ledger-abci` supplies the deterministic CometBFT boundary. Clients
obtain finalized entries through `thunderbolt-ledger-comet-client`.

Key rotation and recovery require an explicitly domain-separated governance
rule before operators enable them.

## Side-channel boundary

Production code in this crate never accepts an actor secret key and never signs.
It hashes public proposal fields and delegates BIP340 verification to
libsecp256k1 through the Rust `secp256k1` crate. Test-only helpers use fixed
secret keys solely to generate verification fixtures and remain outside the
production API. Every input handled by this contract is public.
