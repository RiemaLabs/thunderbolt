# Production roadmap

Bitcoin Thunderbolt `v1.0.0-rc.1` is a library and reference Ledger release. Mainnet is disabled. The current daemon cannot run the complete Open, Invoice, Transfer, committee update, and Finalize lifecycle.

This roadmap records the remaining engineering and review gates. It is not a release-date commitment.

## Current foundation

The repository contains:

- the proof and threshold primitives in `thunderbolt-core`
- bounded public messages and deployment bindings in `thunderbolt-wire`
- deterministic Ledger events, reduction, and SQLite persistence
- a Ledger-only `thunderboltd` and control CLI
- a local Holder and Recipient engine
- a one-share committee member engine
- a Trusted Verifier for Invoice and Transfer
- an encrypted participant Keystore
- a validated Bitcoin Core client and chain cursor

The last five items are libraries. They have no daemon services, CLI commands, deployment topology, or end-to-end lifecycle test.

## Protocol v2

Protocol v2 must define one canonical deployment and channel binding across every crate. It must include the Bitcoin network, genesis hash, deployment ID, full funding outpoint, committee epoch and descriptor, parameter suite, and anchor base. Invoice ID, transfer step, and prior committed event belong to each operation.

The event contract also needs:

- actor public keys and signatures over canonical proposal bytes
- separate participant proposals, verifier evidence, and Ledger commit records
- an explicit threshold-Invoice message that binds the restricted Invoice proof to the VESS distribution
- an Open message and verifier
- an `R_own` proof and Finalize message bound to `(ctx_id, s, P, X_s, tx)`
- golden vectors and migration rules for every canonical digest

Verification must run inside the same storage write transaction that selects the channel head, referenced Invoice, and trusted Ledger time. The transaction must persist the committed entry, evidence, idempotency mapping, snapshot, and notification outbox before it returns success.

## Multi-process regtest

The first integrated topology should run one Bitcoin Core regtest node, one Ledger, two Holder processes, and three committee-member processes with a threshold of two.

Each role needs a local service, a durable Ledger cursor, an outbox, restart recovery, and a control API. The test must cover a Recipient Invoice, current-Holder Transfer, two independent committee share updates, Recipient credential recovery, and duplicate delivery. It must kill processes after external commit but before local acknowledgement and prove that retries neither repeat a share update nor reuse signing material.

Bitcoin tests must cover network mismatch, funding confirmation, broadcast response loss, daemon restart, and a funding or closing reorganization. A test-only Open or Finalize fixture must be labeled as such and cannot support a production-readiness claim.

## Cryptographic completion

A faithful on-chain lifecycle still needs reviewed designs for:

- initial committee DKG or provisioning and public consistency with the fixed lock key `P`
- the concrete NUMS anchor base and parameter-suite identifier
- the production Paillier size, including the paper's 3072-bit evaluation and a versioned wire migration from the RC's 2048-bit format
- `R_own` proof generation and verification
- combined-key Holder plus `t`-of-`n` FROST signing under `P`
- nonce reservation, consumption, aggregation, abort, and recovery rules
- committee rotation and proactive resharing

The paper's Fiat-Shamir proofs establish the standalone proof relations. They do not by themselves instantiate the UC `F_NIZK` interface assumed by the paper's composition theorem. Public security claims must keep that distinction.

## Production Ledger and release

The single SQLite Ledger is a development service. A production Ledger must establish append-only persistence, one committed order per channel, and eventual inclusion and retrieval under the stated fault model. That requires a reviewed consensus or external-log design, authenticated participant identities, protocol transport, and recovery procedures.

Mainnet remains disabled until the integrated system passes multi-process restart and reorganization tests, production observability and backup drills, dependency and release checks, and an independent security audit with critical findings resolved.
