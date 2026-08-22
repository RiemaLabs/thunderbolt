# Security

Bitcoin Thunderbolt moves control of Bitcoin and must be operated as security-critical software. `v1.0.0-rc.1` is a reference Ledger for development and regtest. Mainnet is disabled.

The workspace contains an encrypted Keystore, a one-share committee engine, a Holder engine, a Trusted Verifier, and a validated Bitcoin Core client. The node library can inject the Trusted Verifier into its atomic Invoice and Transfer append path. The shipped daemon does not configure that verifier or load the other role libraries, so their presence does not make the current service a complete or production-safe protocol deployment.

This guide covers deployment controls. The protocol assumptions are in [Threat model](threat-model.md), and private vulnerability reporting is in [SECURITY.md](../SECURITY.md).

## Current security milestone

The focused review of clean HEAD `6ca2c42` found no unresolved Critical, High, or Medium code finding within the reviewed Ledger v2, protocol v2, Keystore, Holder-adapter, and committee-adapter boundaries.

This is not production approval. Version 2 has BIP340 actor-signed proposals and concurrent Invoice semantics as standalone libraries, but the executable daemon still runs version 1 without a production verifier. The repository has no finality receipt, ABCI runtime, durable version 2 request index, production rollback-floor backend, role daemons, outboxes, Ledger cursors, or Bitcoin settlement path.

The resolved items and exact review boundary are recorded in [Security milestone](security-milestone-2026-08-21.md).

## Key and share handling

- Generate Holder keys, committee shares, transport keys, and release keys with an operating-system CSPRNG.
- Keep Holder secrets and committee shares encrypted at rest. Store the wrapping key in an OS keyring, HSM, hardware-backed keystore, or a separate protected file.
- Never put a seed, private key, committee share, API credential, password, or control token in TOML, command arguments, logs, issue reports, test fixtures, or source control.
- Run each committee share under a separate administrative identity. Production committee operators should also use separate hosts and failure domains.
- Set data directories and credential files to owner-only access. Refuse startup if ownership or permissions are unsafe.
- Lock memory and zeroize secret buffers where the platform and library support it. Do not rely on zeroization as a substitute for host security.
- Persist threshold-signing sessions before releasing a partial signature. Mark every nonce as consumed even after a crash or timeout.

## Control access

The current administrative endpoint is loopback HTTP on port `19736` by default. Runtime validation rejects remote binding and built-in TLS. The configured Unix socket path is reserved and is not listened on.

Health routes are public. Every other `/v1` route requires a bearer token loaded from an owner-only regular file. Scopes are `read`, `write`, `operator`, and `admin`. Event submission also requires the token identifier to match the Ledger actor participant identifier. Higher scope does not permit actor impersonation.

Use `thunderbolt-cli config show` to inspect redacted configuration and `getinfo` to confirm node identity, network, role, and verification mode.

## Protocol transport

- Use TLS 1.3 with mutual authentication for committee traffic.
- Pin committee membership keys in a signed descriptor.
- Sign each protocol entry over a canonical, domain-separated digest. Do not sign raw JSON or raw protobuf bytes.
- Apply message-size limits before allocation and proof-verification limits before expensive work.
- Use deadlines, bounded queues, exponential retry with jitter, and per-identity rate limits.
- Retry a mutation only with the original request identifier.
- Keep the public protocol listener separate from the administrative listener.

## Ledger safety

A production Thunderbolt Ledger must provide the three guarantees defined by the protocol:

1. A committed entry cannot be removed or changed.
2. All participants see one order of entries within a channel.
3. Valid entries from honest participants are eventually included and committed entries remain retrievable.

A local SQLite service or single server is useful for development, but it creates a trusted point of ordering and availability. Do not describe that profile as Byzantine fault tolerant. A production profile needs an implementation and review of the stated fault model, such as a deterministic application over a suitable BFT consensus system.

`thunderbolt-ledger` now defines the chain-scoped signed proposal, executed-block commitment, application hash, and ordered Merkle-proof contract for a deterministic version 2 application. These types prove deterministic execution, not validator finality.

The current recommendation is to expose that application through ABCI and replicate it with CometBFT. This remains planned architecture. The repository contains no CometBFT dependency, ABCI service, validator configuration, quorum or light-client receipt, deployment, or integration test. The validator set and its relationship to the Threshold Committee also remain design work.

Ledger signatures do not replace consensus guarantees. Consensus transport authentication does not replace entry signatures.

## Durable state and backup

The current Ledger commits the immutable event and derived public channel snapshot in one SQLite transaction before acknowledging success. It does not store Holder secrets, committee shares, or signing material.

`thunderbolt-keystore` supplies encrypted multi-record transactions, idempotent receipts, and permanent consumed-nonce tombstones. `VaultCheckpoint` binds a revision to the exact encrypted-file digest, and all secret reads and outputs remain fenced until external checkpoint CAS succeeds. Concrete Holder and committee adapters implement their engine storage traits and support bounded pruning after external finalization.

The repository deliberately has no production `RollbackFloorStore`. A production backend must live in an independent authenticated trust domain and key CAS by the complete vault identity. A sibling file is not a production floor. Exact anchored backups can be restored, but there is no automatic recovery protocol for a process killed after local encrypted persistence and before checkpoint advancement.

Pruning also has limits. The Holder adapter loads retained history eagerly, while the committee replay journal has a 512 KiB state-record ceiling. Transaction-receipt and finalized-idempotency pruning require independent durable request history. Nonce tombstones are never pruned.

`database backup` creates a verified SQLite backup but does not encrypt it. Protect the backup directory with filesystem or encrypted-volume controls. Production backups must be encrypted and include enough metadata to identify the network, daemon identity, schema version, last event hash, and channel sequence.

Prevent two running daemons from using the same identity or database. A copied database can cause stale-state signing or nonce reuse even if the copies never run at the same time.

Restore rules:

1. Stop the old instance and preserve its data directory.
2. Verify the backup signature or authenticated checksum.
3. Restore to a new empty directory.
4. Start without mutation access and reconcile Ledger and Bitcoin state.
5. Enable mutations only after every channel reaches a known committed sequence.

## Bitcoin settlement

`thunderbolt-bitcoin` provides bounded Bitcoin Core RPC, network and genesis validation, a reorganization-aware chain cursor, and pure funding and closing-transaction checks. It is not connected to `thunderboltd`, contains no wallet or signing code, and does not complete Open or Finalize.

The backend passed the measured live gate on official Bitcoin Core v31.1.0. The run checked verified release metadata, an isolated zero-peer regtest, network and genesis, raw transaction and coinbase UTXO handling, the exact 100-confirmation maturity boundary, a one-block disconnect and distinct replacement, graceful same-datadir restart, and a full post-restart rerun. The ignored harness does not pin or download Bitcoin Core and is not an automatic CI guarantee. See [Testing](testing.md).

- Use a validated Bitcoin Core backend for production.
- Bind all channel state to the selected Bitcoin network and funding outpoint.
- Wait for the configured confirmation policy before treating Open or Finalize as stable.
- Track replaced, evicted, and reorganized transactions.
- Build and verify the exact closing transaction before threshold signing starts.
- Bind each partial signature to the channel, current step, combined nonce, fee policy, and transaction digest.
- Refuse mainnet startup until the release explicitly enables it.

## Logs, health, and target metrics

Logs must be structured and redacted. Safe fields include protocol version, network, channel identifier, sequence, event hash, duration, status code, and peer identity. Unsafe fields include secrets, shares, seeds, passwords, tokens, raw decrypted values, wrapping keys, and threshold nonce material.

The RC exposes loopback liveness and readiness routes but no metrics endpoint. A future metrics service should stay on loopback unless an authenticated monitoring network is configured and should cover:

- Ledger sequence lag and failed submissions
- proof generation and verification latency
- committee quorum and member health
- pending transfer and finalization sessions
- Bitcoin height lag, confirmations, and reorganizations
- database latency, backup age, WAL growth, and recovery results
- rejected events, rate limiting, queue depth, and control authorization failures

Alert on quorum loss, stalled sequences, stale Bitcoin state, repeated proof failures, backup verification failure, and any attempt to start a duplicate identity.

## Dependency and build controls

- Keep `Cargo.lock` under review and build releases from a clean tag.
- Run vulnerability, license, secret, and provenance scans on every release candidate.
- Review cryptographic and serialization dependency updates manually.
- Produce a software bill of materials, checksums, and signed release artifacts.
- Rebuild artifacts in a second clean environment and compare results where reproducibility is supported.
- Retain the exact source commit, toolchain, and build instructions for every release.

## Mainnet approval gates

Mainnet stays disabled until all of these gates pass:

- reconcile the RC's 2048-bit Paillier wire parameter with the paper's 3072-bit evaluation parameter, then regenerate and audit compatibility vectors
- production review of the deterministic event state machine and canonical wire format
- production role runtimes built around the landed Keystore adapters, with outboxes, Ledger cursors, backup, restore, and crash recovery
- a production rollback-floor backend, killed-between-persistence-and-floor recovery, and compaction or epoch rotation for retained role history
- integrated Open, Transfer, committee update, and Finalize settlement path
- reviewed Open DKG or provisioning, including consistency between committee shares and the fixed lock key
- concrete `R_own` verification for the current Holder and exact closing context
- combined-key Holder plus FROST signing under `P`, with audited nonce lifecycle and aggregation
- resolved constant-time analysis for secret Paillier operations
- one independently administered committee process per share
- Ledger implementation that meets the documented fault model
- Bitcoin Core confirmation, fee, mempool, and reorganization handling
- authenticated transport and least-privilege control access
- a concrete authenticated quorum-receipt verifier, ABCI/CometBFT integration, durable version 2 request index, and migration from the version 1 daemon
- multi-process tests for restart, replay, duplicates, ordering, quorum loss, and finalization races
- removal of mock keys, fixed nonces, production panics, and unfinished signing paths from release binaries
- dependency, license, secret, and cryptographic review
- independent external security audit with critical findings resolved
- signed release artifacts and an operator rollback plan

Passing unit tests or reproducing paper benchmarks does not satisfy these gates.

See [Production roadmap](roadmap.md) for the order in which the runtime, protocol v2, and deployment gates are intended to land.

## Development demo warning

Normal daemon startup rejects event submission because no production verifier is configured. The executable does not use `thunderbolt-ledger`, the protocol v2 reducer, the role adapters, or an ABCI service. The version 1 node library can inject a Trusted Verifier for Invoice and Transfer, but the executable has no configuration for it and Open and Finalize still fail closed. `--development-allow-unverified-demo-events` is accepted only on development regtest. In that mode, the daemon rejects client-supplied verification evidence and inserts synthetic evidence labeled `development-unverified-demo`.

The demo flag does not validate proofs, Bitcoin transactions, signatures, or committee quorums. Treat every resulting database as test data.
