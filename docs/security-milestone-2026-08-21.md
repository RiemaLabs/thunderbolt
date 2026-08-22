# Security milestone: library integration boundary

This report covers clean HEAD `6ca2c42` on `release/1.0`. It reviews the landed library boundaries added after the earlier reference-Ledger review:

- stable version 2 channel and operation bindings
- chain-scoped BIP340 signed proposals, executed blocks, application hashes, and Merkle proofs
- deterministic protocol v2 reduction with concurrent Invoices and consensus time
- transaction-scoped storage verification and node verifier injection
- Holder threshold Invoice construction and committee Recipient-share binding
- one-share committee update and signing-session guards
- transactional multi-record Keystore, rollback checkpoints, and concrete Holder and committee adapters
- Bitcoin Core backend validation and live regtest evidence
- default isolation of legacy settlement and single-process committee code

## Result

The focused milestone review found no unresolved Critical, High, or Medium code finding within the reviewed Ledger v2, protocol v2, Keystore, Holder-adapter, and committee-adapter boundaries.

This result is not a production approval, full protocol audit, cryptographic proof audit, consensus-finality review, or review of a deployed network. `thunderboltd` still runs a verifierless version 1 single Ledger. Mainnet remains disabled. The system-level gaps below sit outside the reviewed library invariants and remain release-blocking.

## Resolved milestone items

Transaction-scoped verification
: `append_verified_proposal` deduplicates an evidence-free proposal under the SQLite writer lock, loads the authoritative channel and pending Invoice, samples one trusted Ledger time, invokes the verifier, and commits the entry, evidence, snapshot, and retry mapping together. The node can inject `TrustedVerifier` for Invoice and Transfer. Client evidence, mismatched verifier identities, wrong timestamps, and zero statement digests fail closed.

Signed Ledger v2 contract
: `SignedProposalV2` binds the Ledger chain, complete channel context, predecessor, actor-scoped request digest, x-only BIP340 key, derived participant ID, role, event kind, and event bytes. Executed blocks bind external height and time, proposal order, an ordered Merkle root, and the previous application hash. Successor and inclusion proofs are self-checking. The types deliberately make no consensus-finality claim.

Protocol v2 state machine
: The reducer accepts only authenticated executed entries, pins one Ledger chain, uses positive monotonic consensus time, maintains a bounded concurrent Invoice map, consumes one selected Invoice by exact entry hash, invalidates stale-step Invoices after Transfer, and orders Finalize. Proof verification remains behind deterministic external hooks.

Recipient-share binding
: The Holder threshold path creates a Recipient share proof and VESS distribution over the same refresh. The committee and Trusted Verifier bind the reserved Recipient identifier, proof context, key, ciphertext, anchor, public delta, package digest, committed Invoice, committed Transfer, and Ledger receipt boundary before a share update. The implemented `tb/share` transcript is not represented as the paper's exact `R_inv^thr` transcript.

Keystore rollback and nonce handling
: The version 2 vault supports bounded namespaced records, atomic multi-record updates, idempotent receipts, permanent consumed-nonce tombstones, and exact `VaultCheckpoint` values that combine revision with encrypted-state digest. Secret reads and callback output remain fenced until external checkpoint CAS succeeds. Exact anchored backups can be restored, and pruning requires externally finalized request history.

Concrete role adapters
: `KeystoreSecretVault` and `KeystoreCommitteeVault` implement the engine storage traits over fenced Keystore transactions. Creation, open, reads, updates, backup, replay, ambiguous-write handling, and pruning check the complete deployment-scoped checkpoint. Provisioning rejects non-empty or orphaned role state, and stale or forked files fail before secret output.

Version 2 Bitcoin binding
: The stable channel binding includes the Bitcoin network, exact matching genesis hash, complete non-null funding outpoint, deployment, committee descriptor and epoch, protocol suite, and anchor parameter suite. Invoice ID and positive Transfer step are separate operation inputs and cannot change the stable channel context.

Funding maturity and live backend
: Funding expectations reject zero-confirmation policy and enforce the exact Bitcoin coinbase maturity boundary. The official Bitcoin Core v31.1.0 live gate covered the boundary at 100 confirmations, network and genesis mismatch, cursor synchronization, raw transaction and coinbase UTXO checks, a one-block reorganization, distinct replacement, graceful same-datadir restart, and a full post-restart rerun.

Secret and legacy isolation
: Holder cryptographic intermediates use zeroizing storage where the current libraries expose it. The static two-key settlement prototype and single-process committee fixtures are absent from default release builds and require the explicit `legacy-research`, `insecure-regression`, or `insecure-regtest` features.

## Remaining production blockers

- The executable daemon remains version 1 and has no configured production verifier, version 2 application, role service, or ABCI path.
- The repository has no production `RollbackFloorStore` in an independent authenticated trust domain and no automatic recovery for a process killed between local persistence and checkpoint advancement.
- `thunderbolt-ledger` has no CometBFT or ABCI runtime, validator finality receipt, trusted header chain, persistent channel database, or durable cross-block request index.
- The committee's `LedgerCommitmentVerifier` remains abstract. Holder `DurableAcknowledgement` still has a public raw constructor and requires a trusted Ledger adapter.
- Holder and committee role daemons, durable outboxes, Ledger cursors, and Bitcoin settlement are missing.
- Version 1 remains the shipped runtime contract. Version 2 has no coordinated activation or migration path.
- Open still needs reviewed DKG or provisioning and public consistency with `P`. Finalize still needs `R_own` and combined-key Holder plus FROST signing.
- The 2048-bit RC Paillier format remains different from the paper's 3072-bit evaluation parameter.
- The constant-time argument for secret Paillier operations remains unresolved. See [Committee constant-time analysis](../crates/thunderbolt-committee/CONSTANT_TIME.md).
- Holder's eager append-only history and the committee's 512 KiB replay journal need compaction or epoch rotation. Receipt pruning does not compact engine history, and nonce tombstones must remain permanent.
- Multi-process role recovery, Bitcoin settlement, transport security, observability, release operations, and an independent external audit remain incomplete.

## Validation evidence

- The final full workspace run recorded 268 passed, 0 failed, and 1 intentionally ignored live Bitcoin test. A fresh final all-target workspace check passed.
- Focused suites at the final boundary passed: Ledger 13, protocol 44, Keystore 27 plus 3 compile-fail doctests, Holder 21, and committee 22.
- Strict package Clippy, formatting, rustdoc, and documentation checks passed for the landed component changes.
- The official Bitcoin Core v31.1.0 live gate passed with the evidence recorded in [Testing](testing.md).
- An isolated 4-CPU, 16-GiB Linux gate passed on ancestor `bcdf250`: formatting, workspace check, 127 tests, strict Clippy, warnings-as-errors rustdoc, and 3 doctests. Later final adapter regressions have focused local coverage but were not part of that Linux run.
- The reviewed stable worktree at `6ca2c42` was clean.

See [Testing](testing.md), [Security](security.md), and [Production roadmap](roadmap.md) for the evidence and remaining release gates.
