# Roadmap

Version 1.0 establishes the stable open source baseline for Bitcoin Thunderbolt.

## Landed foundation

- role-aware daemon and owner-only local control
- strict Ledger, Holder, and committee configuration
- deterministic Ledger application and bounded ABCI server
- authenticated CometBFT RPC and light-client finality
- durable Holder and committee service state
- encrypted participant vaults and external rollback-floor contracts
- Bitcoin Core validation, chain tracking, and settlement checks
- bounded wire, proposal, block, query, and snapshot formats
- fixed-width Paillier arithmetic foundation and ownership proof

## Version 1.0 integration

Version 1.0 brings the Ledger and rollback-floor applications, Holder and committee services, authenticated CometBFT clients, Bitcoin Core backend, strict runtime configuration, encrypted storage, and operator control into one release. Concrete deployment handlers and trust material remain explicit operator-provided integration points.

## Cryptography

Before mainnet activation, the project will complete:

- production proof construction on the fixed Paillier parameter set
- migration of Holder and committee engines to the bounded proof messages
- distributed key generation and authenticated provisioning
- Holder ownership verification in the exact closing context
- combined Holder and committee threshold signing
- nonce persistence, retry, abort, and recovery rules
- external review of the construction and implementation

The detailed signing decision is recorded in the [signing protocol design](signing-protocol-v2.md).

## Version 1.0 release package

The release package includes:

- daemon and CLI binaries without demo behavior in the default feature graph
- CometBFT and Bitcoin Core configuration templates
- Ledger, Holder, and committee service units
- owner-only filesystem layout and recovery instructions
- container and multi-process regtest examples
- checksums, signed release metadata, and a software bill of materials

## Mainnet activation

Mainnet follows the complete lifecycle test, production key and checkpoint providers, operational recovery drills, dependency and license review, and an independent security audit. The activation will use an explicit release rather than a configuration-only switch.
