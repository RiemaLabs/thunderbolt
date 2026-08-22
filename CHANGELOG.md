# Changelog

All notable changes to Bitcoin Thunderbolt are recorded here. The project follows semantic versioning for software releases and versions the protocol event format separately.

## [Unreleased]

### Added

- Public repository documentation for architecture, operator roles, configuration, security, API design, release management, and history sanitization.
- Apache License 2.0, project notice, contribution policy, governance, support, security reporting, and community templates.
- Explicit `v1.0.0-rc.1` status with mainnet disabled pending implementation, testing, and audit gates.
- Reference Ledger daemon, loopback JSON API, operator CLI, strict configuration, bearer-token authorization, deterministic protocol reducer, and durable SQLite storage.

### Security

- Documented historical secret-bearing files and oversized generated build history that must be removed before publication.
- Defined private vulnerability reporting and mainnet approval gates.

## [1.0.0-rc.1] - Unreleased

The first RC packages a Ledger-role daemon and operator CLI for development and regtest. Holder and committee runtimes, production verification, Bitcoin settlement, metrics, and a production Ledger fault model are unavailable.
