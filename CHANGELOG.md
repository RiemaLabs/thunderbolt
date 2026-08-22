# Changelog

All notable changes to Bitcoin Thunderbolt are recorded here. The project follows semantic versioning for software releases and versions the protocol event format separately.

## [Unreleased]

### Added

- Public repository documentation for architecture, operator roles, configuration, security, API design, release management, and history sanitization.
- Apache License 2.0, project notice, contribution policy, governance, support, security reporting, and community templates.
- Explicit `v1.0.0-rc.1` status with mainnet disabled pending implementation, testing, and audit gates.
- Reference Ledger daemon, loopback JSON API, operator CLI, strict configuration, bearer-token authorization, deterministic protocol reducer, and durable SQLite storage.
- Fail-closed Bitcoin Core access with network and genesis validation, bounded RPC, reorganization-aware chain cursors, and funding and closing checks.
- Transactional Holder and Recipient state engine for credentials, the v1 single-committee Invoice path, Transfers, and idempotent Ledger acknowledgements.
- One-share committee member engine with committed-transfer binding, replay-safe refresh state, and fail-closed signing-session guards.
- Trusted verification bridge for bounded Invoice and Transfer artifacts.
- Encrypted participant Keystore with owner-only files, authenticated backup and restore, and exclusive locking.

### Security

- Documented historical secret-bearing files and oversized generated build history that must be removed before publication.
- Defined private vulnerability reporting and mainnet approval gates.

## [1.0.0-rc.1] - Unreleased

The first RC packages a Ledger-role daemon and operator CLI for development and regtest. Holder, committee, verifier, Keystore, and Bitcoin Core libraries are included but are not wired into the daemon. A complete Open-to-Finalize lifecycle, DKG, `R_own`, combined-key threshold signing, production Ledger fault model, metrics, and mainnet support are unavailable.
