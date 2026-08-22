# Security milestone: library integration boundary

This report covers stable HEAD `17fc4c1` on `release/1.0`. It reviews the landed library boundaries added after the earlier reference-Ledger review:

- stable version 2 channel and operation bindings
- transaction-scoped storage verification and node verifier injection
- Holder threshold Invoice construction and committee Recipient-share binding
- one-share committee update and signing-session guards
- transactional multi-record Keystore and rollback controls
- Bitcoin Core backend validation and live regtest evidence
- default isolation of legacy settlement and single-process committee code

## Result

The focused milestone review found no unresolved Critical or High defect within these landed library boundaries.

This result is not a production approval, full protocol audit, cryptographic proof audit, or review of a deployed network. `thunderboltd` still runs as a verifierless single Ledger. Mainnet remains disabled. The system-level gaps below sit outside the completed library invariants and remain release-blocking; several carry High impact if a runtime treats the current abstractions as finished capabilities.

## Resolved milestone items

Transaction-scoped verification
: `append_verified_proposal` deduplicates an evidence-free proposal under the SQLite writer lock, loads the authoritative channel and pending Invoice, samples one trusted Ledger time, invokes the verifier, and commits the entry, evidence, snapshot, and retry mapping together. The node can inject `TrustedVerifier` for Invoice and Transfer. Client evidence, mismatched verifier identities, wrong timestamps, and zero statement digests fail closed.

Recipient-share binding
: The Holder threshold path creates a Recipient share proof and VESS distribution over the same refresh. The committee and Trusted Verifier bind the reserved Recipient identifier, proof context, key, ciphertext, anchor, public delta, package digest, committed Invoice, committed Transfer, and Ledger receipt boundary before a share update. The implemented `tb/share` transcript is not represented as the paper's exact `R_inv^thr` transcript.

Keystore rollback and nonce handling
: The version 2 vault supports bounded namespaced records, atomic multi-record compare-and-swap updates, idempotent transaction receipts, authenticated revisions, and permanent consumed-nonce tombstones. Committee open requires an externally anchored positive minimum revision. A committee vault below that floor is rejected before secret access, and generic committee restore is forbidden.

Version 2 Bitcoin binding
: The stable channel binding includes the Bitcoin network, exact matching genesis hash, complete non-null funding outpoint, deployment, committee descriptor and epoch, protocol suite, and anchor parameter suite. Invoice ID and positive Transfer step are separate operation inputs and cannot change the stable channel context.

Funding maturity and live backend
: Funding expectations reject zero-confirmation policy and enforce the exact Bitcoin coinbase maturity boundary. The official Bitcoin Core v31.1.0 live gate covered the boundary at 100 confirmations, network and genesis mismatch, cursor synchronization, raw transaction and coinbase UTXO checks, a one-block reorganization, distinct replacement, graceful same-datadir restart, and a full post-restart rerun.

Secret and legacy isolation
: Holder cryptographic intermediates use zeroizing storage where the current libraries expose it. The static two-key settlement prototype and single-process committee fixtures are absent from default release builds and require the explicit `legacy-research`, `insecure-regression`, or `insecure-regtest` features.

## Remaining production blockers

- The executable daemon has no configured production verifier. Open and Finalize fail closed even when the node library receives an Invoice and Transfer verifier.
- Participant proposals have no actor signature. Bearer-token identity matching is a control check, not persistent cryptographic authentication.
- The committee exposes a `LedgerCommitmentVerifier` trait, but no concrete signed or consensus-backed quorum receipt exists.
- Holder and committee engines have no daemon services or concrete private-vault adapters. Durable outboxes and Ledger cursors are also missing.
- Version 1 remains the active message and Ledger contract. The stable version 2 binding has no coordinated migration or activation path.
- The reducer permits one pending Invoice, while the paper's ideal state uses a pending-Invoice set. This is an explicit product-semantics gap.
- Open still needs reviewed DKG or provisioning and public consistency with `P`. Finalize still needs `R_own` and combined-key Holder plus FROST signing.
- The runnable Ledger is one SQLite service. CometBFT is only the planned production recommendation and has no implementation in this repository.
- The 2048-bit RC Paillier format remains different from the paper's 3072-bit evaluation parameter.
- The constant-time argument for secret Paillier operations remains unresolved. See [Committee constant-time analysis](../crates/thunderbolt-committee/CONSTANT_TIME.md).
- Multi-process role recovery, Bitcoin settlement, transport security, observability, release operations, and an independent external audit remain incomplete.

## Validation evidence

- 59 focused Keystore, node, and storage tests passed, covering restart, rollback, tampering, concurrency, replay, and HTTP integration.
- The 9-test Holder suite passed, including the threshold Invoice property cases.
- Formatting, strict Clippy, rustdoc, and documentation tests passed for the landed component changes.
- The official Bitcoin Core v31.1.0 live gate passed with the evidence recorded in [Testing](testing.md).
- The reviewed stable worktree at `17fc4c1` was clean.

See [Testing](testing.md), [Security](security.md), and [Production roadmap](roadmap.md) for the evidence and remaining release gates.
