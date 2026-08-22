# Thunderbolt Ledger contract

`thunderbolt-ledger` defines the deterministic protocol-v2 application contract
for Bitcoin Thunderbolt. It is suitable for a replicated state machine, but it
is not itself a network, consensus engine, ABCI server, database, or verifier.

## What is signed

An actor submits a `SignedProposalV2` containing:

- a consensus `ledger_chain_id` and complete stable `ChannelBindingV2`;
- the per-channel sequence and prior entry hash;
- a request nonce whose request digest is derived from the Ledger chain,
  channel, actor key, and role;
- the explicit `bip340_v1` key algorithm, x-only actor key, and role;
- an event kind and non-empty canonical event bytes, bounded at 256 KiB.

The participant id is derived from the validated BIP340 key. It is never
accepted as a caller-supplied name. The signature covers a domain-separated
binary transcript in which every label and value is length-prefixed. Serde and
JSON representations are not signing formats.

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

Neither API supplies validator signatures, a quorum certificate, or a trusted
header chain. A CometBFT quorum or light-client receipt is a separate future
capability and must be verified before an operator treats execution output as
consensus-final.

## Integration boundary

The future ABCI application must still:

- compare `ledger_chain_id` with its configured consensus chain;
- validate the first proposal for each channel against the persisted channel
  head, then use the same-block predecessor checks here;
- persist a durable, cross-block `request_digest -> entry_hash` mapping and
  reject the same request digest if it ever names a different entry hash;
- verify that block height, prior application hash, and prior consensus time
  extend trusted executed state with `validate_successor`;
- decode canonical event bytes into the exact typed event schema and run the
  protocol-v2 reducer before storing an executed block atomically;
- verify a future CometBFT quorum or light-client receipt separately before
  exposing any consensus-finality capability.

Key rotation and key recovery are not specified by protocol v2. The governance
process for authorizing either operation is also undecided. This crate does not
invent those rules; a future version must define and domain-separate them before
operators can enable rotation or recovery.

## Side-channel boundary

Production code in this crate never accepts an actor secret key and never signs.
It hashes public proposal fields and delegates BIP340 verification to
libsecp256k1 through the Rust `secp256k1` crate. Test-only helpers use fixed
secret keys solely to generate verification fixtures and remain outside the
production API. Production code was manually reviewed for secret-dependent
branches, indexing, and division; none exist because every input handled by
this contract is public.
