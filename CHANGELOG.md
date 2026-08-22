# Changelog

All notable changes to Bitcoin Thunderbolt are recorded here. The project follows semantic versioning for software releases and versions the protocol event format separately.

## [Unreleased]

## [1.0.0] - 2026-08-22

Bitcoin Thunderbolt 1.0.0 is the first stable open source release maintained by Nubit. It turns the research protocol into a complete open source systems foundation spanning cryptography, state machines, durable services, consensus integration, Bitcoin integration, operator tooling, and release automation.

### Added

- Deterministic signed Ledger and rollback-floor applications, bounded ABCI servers, durable SQLite state, application hashes, request indexes, and inclusion proofs.
- Authenticated bounded CometBFT RPC, durable light-client finality coordination, and typed finalized capabilities for role services.
- Durable Holder and committee services with encrypted vaults, outboxes, Ledger cursors, checkpoint fencing, replay handling, and restart reconciliation.
- Canonical version 2 protocol, wire, proof, channel, and operation bindings scoped to the Bitcoin network, funding outpoint, deployment, committee, proof suite, and anchor suite.
- Fixed-width Paillier support, ownership proofs, and trusted verification interfaces for bounded Invoice and Transfer artifacts.
- Strict role configuration, process locking, owner-only Unix-socket control, redacted diagnostics, and lifecycle commands through `thunderboltd` and `thunderbolt-cli`.
- Fail-closed Bitcoin Core access with network and genesis validation, bounded RPC, maturity and confirmation policy, reorganization-aware cursors, and funding and settlement checks.
- A three-binary default release graph, systemd and container assets, source and platform archives, SBOM generation, checksum tooling, and GitHub Actions release publication.

### Changed

- Replaced the legacy loopback HTTP and bearer-token operator path with an owner-only local Unix socket.
- Excluded legacy settlement code and test-only committee fixtures from default release builds; they remain available only through explicit non-default features.
- Kept version 2 as a separate library surface rather than silently interpreting version 2 entries through legacy version 1 interfaces.

### Security

- Bounded public codecs, queues, snapshots, requests, and retained state to make resource limits part of the protocol boundary.
- Bound signatures, proofs, credentials, and finalized capabilities to their exact network, deployment, channel, operation, and finality contexts.
- Added encrypted checkpoint-fenced participant storage and fail-closed handling for replay, corruption, stale state, ambiguous writes, and finality loss.

### Deployment scope

- Release archives contain the reusable software and operator assets. Deployment identities, trust roots, credentials, checkpoint providers, role handlers, and environment-specific configuration remain operator-provisioned.
