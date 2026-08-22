# Production roadmap

Bitcoin Thunderbolt `v1.0.0-rc.1` is a library and reference Ledger release. Mainnet is disabled. The current daemon cannot run the complete Open, Invoice, Transfer, committee update, and Finalize lifecycle.

This roadmap records the remaining engineering and review gates. It is not a release-date commitment.

## Current foundation

The repository contains:

- the proof and threshold primitives in `thunderbolt-core`
- bounded version 1 public messages and a stable version 2 binding in `thunderbolt-wire`
- deterministic Ledger events, reduction, and transaction-scoped verified SQLite persistence
- a Ledger-only `thunderboltd` and control CLI
- a local Holder and Recipient engine with single-committee and threshold Invoice paths
- a one-share committee member engine with Recipient-share binding
- a Trusted Verifier for Invoice and Transfer, plus an injection boundary in `thunderbolt-node`
- an encrypted transactional multi-record participant Keystore with external rollback floors
- a validated Bitcoin Core client and chain cursor

The role and backend components are libraries. They have no daemon services, CLI commands, or complete deployment topology. The shipped daemon does not configure the Trusted Verifier.

## Protocol v2

`ChannelBindingV2` and `OperationBindingV2` now define the stable proof scope. They include the protocol suite, Bitcoin network and exact genesis, deployment ID, full funding outpoint, committee epoch and descriptor digest, and anchor parameter-suite digest. Invoice ID and positive Transfer step remain operation inputs.

Version 1 remains the active message, proof-envelope, Holder, committee, verifier, and Ledger contract. Protocol v2 must adopt the stable binding across those consumers without changing version 1 hashes.

The event contract also needs:

- actor public keys and signatures over canonical proposal bytes
- an actor-scoped request identifier and signed participant proposal envelope
- a concrete authenticated quorum receipt consumed by the committee engine's existing receipt trait
- an Open message and verifier
- an `R_own` proof and Finalize message bound to `(ctx_id, s, P, X_s, tx)`
- golden vectors and migration rules for every canonical digest
- a decision to keep the one-pending-Invoice product restriction or adopt the paper's pending-Invoice set

Invoice and Transfer verification now runs inside the same storage write transaction that selects the channel head, referenced Invoice, and trusted Ledger time. The transaction commits the entry, evidence, snapshot, and retry mapping together. A durable notification outbox and actor-scoped request history remain missing.

The Holder threshold path now binds a Recipient `ShareEnvelopeV1` to the exact VESS distribution, and the committee rechecks that binding before its share update. The Recipient proof uses the implemented `tb/share` transcript. It does not claim to instantiate the paper's exact `R_inv^thr` transcript; adopting that transcript would require a new version and review.

## Multi-process regtest

The first integrated topology should run one Bitcoin Core regtest node, one Ledger, two Holder processes, and three committee-member processes with a threshold of two.

Each role needs a local service, a durable Ledger cursor, an outbox, restart recovery, and a control API. The test must cover a Recipient Invoice, current-Holder Transfer, two independent committee share updates, Recipient credential recovery, and duplicate delivery. It must kill processes after external commit but before local acknowledgement and prove that retries neither repeat a share update nor reuse signing material.

The Bitcoin library has passed a measured gate on official Bitcoin Core v31.1.0, including network and genesis checks, exact coinbase maturity, a one-block reorganization, and same-datadir restart. That opt-in harness is ignored in automatic CI. The full topology still needs broadcast response-loss tests and funding or closing reorganization handling at the role-runtime level. See [Testing](testing.md).

A test-only Open or Finalize fixture must be labeled as such and cannot support a production-readiness claim.

## Cryptographic completion

A faithful on-chain lifecycle still needs reviewed designs for:

- initial committee DKG or provisioning and public consistency with the fixed lock key `P`
- the concrete NUMS anchor base and parameter-suite identifier
- the production Paillier size, including the paper's 3072-bit evaluation and a versioned wire migration from the RC's 2048-bit format
- a resolved constant-time argument for secret Paillier operations
- `R_own` proof generation and verification
- combined-key Holder plus `t`-of-`n` FROST signing under `P`
- nonce reservation, consumption, aggregation, abort, and recovery rules
- committee rotation and proactive resharing

The paper's Fiat-Shamir proofs establish the standalone proof relations. They do not by themselves instantiate the UC `F_NIZK` interface assumed by the paper's composition theorem. Public security claims must keep that distinction.

## Production Ledger and release

The single SQLite Ledger is a development service. A production Ledger must establish append-only persistence, one committed order per channel, and eventual inclusion and retrieval under the stated fault model. The current recommendation is a deterministic Thunderbolt application replicated through CometBFT.

CometBFT is planned architecture, not implemented functionality. The repository has no CometBFT dependency, ABCI application, validator configuration, deployment asset, or integration test. Validator governance, its relationship to the Threshold Committee, state synchronization, and recovery procedures remain design work.

Mainnet remains disabled until the integrated system passes multi-process restart and reorganization tests, production observability and backup drills, dependency and release checks, and an independent security audit with critical findings resolved.
