# Changelog

All notable changes to Bitcoin Thunderbolt are recorded here. The project follows semantic versioning for software releases and versions the protocol event format separately.

## [Unreleased]

### Added

- Public repository documentation for architecture, operator roles, configuration, security, API design, release management, and history sanitization.
- Apache License 2.0, project notice, contribution policy, governance, support, security reporting, and community templates.
- Explicit `v1.0.0-rc.1` status with mainnet disabled pending implementation, testing, and audit gates.
- Reference Ledger daemon, loopback JSON API, operator CLI, strict configuration, bearer-token authorization, deterministic protocol reducer, and durable SQLite storage.
- Fail-closed Bitcoin Core access with network and genesis validation, bounded RPC, reorganization-aware chain cursors, and funding and closing checks.
- Transactional Holder and Recipient state engine for credentials, v1 single-committee and threshold Invoice packages, Transfers, and idempotent Ledger acknowledgements.
- One-share committee member engine with Recipient-share and committed-Transfer binding, replay-safe refresh state, and fail-closed signing-session guards.
- Trusted verification bridge for bounded Invoice and Transfer artifacts.
- Stable version 2 channel and operation bindings with exact Bitcoin network, genesis, funding outpoint, deployment, committee, protocol-suite, and anchor-suite scope.
- Transaction-scoped verified Ledger append and optional node injection of the Trusted Verifier for Invoice and Transfer.
- Encrypted transactional multi-record Keystore with compare-and-swap revisions, idempotent receipts, nonce tombstones, external rollback floors, and restricted restore.

### Changed

- Legacy settlement code and single-process committee fixtures are excluded from default release builds and remain available only through the explicit `legacy-research`, `insecure-regression`, or `insecure-regtest` features.

### Security

- Documented historical secret-bearing files and oversized generated build history that must be removed before publication.
- Defined private vulnerability reporting and mainnet approval gates.
- Enforced the coinbase maturity boundary, non-zero verifier statement digests, Recipient-share binding, and zeroization of Holder cryptographic intermediates.

### Validation

- Passed the live Bitcoin backend gate on the official Bitcoin Core v31.1.0 release, including verified release metadata, isolated regtest, exact 100-confirmation funding maturity, a one-block disconnect and distinct replacement, graceful same-datadir restart, and a complete post-restart rerun. The harness remains ignored and environment-gated rather than automatic CI.

## [1.0.0-rc.1] - Unreleased

The first RC packages a Ledger-role daemon and operator CLI for development and regtest. Holder, committee, verifier, Keystore, and Bitcoin Core libraries are included but are not wired into the daemon. A complete Open-to-Finalize lifecycle, DKG, `R_own`, combined-key threshold signing, production Ledger fault model, metrics, and mainnet support are unavailable.
