# Production roadmap

Bitcoin Thunderbolt `v1.0.0-rc.1` is a library and reference Ledger release. Mainnet is disabled. The current daemon cannot run the complete Open, Invoice, Transfer, committee update, and Finalize lifecycle.

This roadmap records the remaining engineering and review gates. It is not a release-date commitment.

## Current foundation

The repository contains:

- the proof and threshold primitives in `thunderbolt-core`
- bounded version 1 public messages and a stable version 2 binding in `thunderbolt-wire`
- chain-scoped BIP340 signed proposals, executed blocks, application hashes, and Merkle proofs in `thunderbolt-ledger`
- a deterministic version 2 reducer with bounded concurrent Invoices and consensus time
- version 1 Ledger events, reduction, and transaction-scoped verified SQLite persistence
- a Ledger-only `thunderboltd` and control CLI
- a local Holder and Recipient engine with single-committee and threshold Invoice paths
- a one-share committee member engine with Recipient-share binding
- a Trusted Verifier for Invoice and Transfer, plus an injection boundary in `thunderbolt-node`
- an encrypted transactional multi-record Keystore and concrete Holder and committee adapters with checkpoint fencing and pruning
- a validated Bitcoin Core client and chain cursor

The version 2 Ledger, reducer, role adapters, and backend components are standalone libraries. They have no ABCI service, consensus finality, daemon services, CLI commands, or complete deployment topology. The shipped daemon remains version 1 and does not configure the Trusted Verifier.

## Protocol v2

`ChannelBindingV2` and `OperationBindingV2` define the stable proof scope. `SignedProposalV2` adds a Ledger chain ID, predecessor, actor-scoped request digest, BIP340 key and signature, role, and canonical event bytes. `ExecutedBlockV2` commits external consensus height and time, ordered entry metadata, an application hash, and Merkle inclusion proofs.

The version 2 reducer consumes these authenticated entries and implements bounded concurrent Invoices, one exact selected Transfer, consensus time, and total-order Finalize. It does not reinterpret version 1 hashes.

Version 1 remains the active daemon, HTTP, SQLite, Holder, committee, and Trusted Verifier contract. The release still needs a coordinated activation and migration plan.

The event contract also needs:

- a persistent ABCI application that decodes events, runs the reducer, and commits channel state atomically with blocks
- a durable cross-block `request_digest -> entry_hash` index
- a concrete authenticated quorum or light-client receipt consumed by the committee and Holder adapters
- production `ExternalVerifierV2` implementations for Open, Invoice, Transfer, and Finalize
- golden vectors and activation rules across every runtime consumer

Version 1 Invoice and Transfer verification runs inside one SQLite write transaction. That path does not store or execute version 2 blocks. Version 2 still needs its own persistence, request index, notification outbox, and recovery rules.

The Holder threshold path now binds a Recipient `ShareEnvelopeV1` to the exact VESS distribution, and the committee rechecks that binding before its share update. The Recipient proof uses the implemented `tb/share` transcript. It does not claim to instantiate the paper's exact `R_inv^thr` transcript; adopting that transcript would require a new version and review.

## Multi-process regtest

The first integrated topology should run one Bitcoin Core regtest node, one Ledger, two Holder processes, and three committee-member processes with a threshold of two.

Concrete Keystore adapters now exist for both roles. Each role still needs a service, durable Ledger cursor, outbox, restart recovery, and control API. The test must cover a Recipient Invoice, current-Holder Transfer, two independent committee share updates, Recipient credential recovery, and duplicate delivery. It must kill processes after local vault persistence but before rollback-floor advancement, and after external commit but before local acknowledgement.

The Bitcoin library has passed a measured gate on official Bitcoin Core v31.1.0, including network and genesis checks, exact coinbase maturity, a one-block reorganization, and same-datadir restart. That opt-in harness is ignored in automatic CI. The full topology still needs broadcast response-loss tests and funding or closing reorganization handling at the role-runtime level. See [Testing](testing.md).

A test-only Open or Finalize fixture must be labeled as such and cannot support a production-readiness claim.

The adapters also need long-lived-state tests. Holder history is eager and append-only, and the committee replay journal has a 512 KiB record ceiling. Production needs compaction or epoch rotation without weakening request replay or nonce tombstones.

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

The version 1 single SQLite Ledger is a development service. `thunderbolt-ledger` now defines the deterministic version 2 application bytes that a replicated system can agree on, but executed blocks and Merkle proofs do not establish finality. The current recommendation is to expose that application through ABCI and replicate it with CometBFT.

CometBFT remains planned architecture. The repository has no CometBFT dependency, ABCI application, validator configuration, quorum receipt, deployment asset, or integration test. Validator governance, its relationship to the Threshold Committee, state synchronization, request indexing, and recovery procedures remain design work.

Mainnet remains disabled until the integrated system passes multi-process restart and reorganization tests, production observability and backup drills, dependency and release checks, and an independent security audit with critical findings resolved.
