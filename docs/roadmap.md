# Roadmap

The `release/1.0` branch is focused on a deployable multi-process Thunderbolt release.

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

## Release integration

The current work connects the concrete Ledger client to Holder and committee run loops, installs the role handlers in the daemon, and packages a complete regtest topology. The integration gate covers independent processes, empty blocks, ambiguous broadcasts, restarts, rollback-floor recovery, quorum loss, and Bitcoin reorganizations.

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

## Operator release

The release package will include:

- daemon and CLI binaries without demo behavior in the default feature graph
- CometBFT and Bitcoin Core configuration templates
- Ledger, Holder, and committee service units
- owner-only filesystem layout and recovery instructions
- container and multi-process regtest examples
- checksums, signed release metadata, and a software bill of materials

## Mainnet activation

Mainnet follows the complete lifecycle test, production key and checkpoint providers, operational recovery drills, dependency and license review, and an independent security audit. The activation will use an explicit release rather than a configuration-only switch.
