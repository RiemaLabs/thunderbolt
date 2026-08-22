# Threat model

This threat model covers the base Thunderbolt protocol and its operator processes.

## Assets

- Holder ownership secrets and credentials
- committee shares and signing nonces
- the fixed channel lock key and funded Bitcoin UTXO
- ordered Ledger history and application state
- participant vaults, backups, and rollback checkpoints
- validator, transport, and release signing keys

## Security properties

### Ownership

Only the current Holder with a valid credential can authorize the next transfer or participate in settlement.

### Committee threshold

Fewer than the configured threshold of committee members cannot reconstruct committee authority or finalize alone.

### Fixed Bitcoin binding

Every operation remains bound to the same network, genesis hash, funding outpoint, deployment, committee, and proof suite.

### Ledger order

Committed entries are immutable, globally ordered, and retrievable. Participants verify consensus finality before acting on an entry.

### Rollback resistance

A copied or restored participant vault cannot produce accepted output from an older checkpoint.

### Crash safety

A restart either resumes the committed transition or rejects the ambiguous state. It does not acknowledge an operation that may not be durable.

## Adversaries

The design considers:

- a malicious Holder or Recipient
- up to the protocol fault bound of corrupted committee members
- Byzantine Ledger validators within the configured CometBFT assumption
- unavailable, stale, equivocating, or misconfigured RPC peers
- malformed or oversized network input
- a local database writer without access to independent checkpoints
- process crashes at durable transition boundaries
- an operator mistake that copies state, reuses an identity, or mixes deployment files

## Trust assumptions

- Bitcoin consensus and the configured Bitcoin Core view are correct after the chosen confirmation policy.
- At least the required committee threshold is honest and available.
- CometBFT satisfies its validator fault assumption and the client starts from an authentic trust root.
- The external rollback-floor and trust-checkpoint providers are independent and authentic.
- Host administrators protect process credentials and do not deliberately extract live secrets from memory.
- Cryptographic parameter registries and deployment manifests are provisioned authentically.

## Boundaries

Actor signatures authenticate proposals but do not prove finality. Merkle proofs authenticate entries to an application hash but do not authenticate the validator decision. TLS authenticates a network peer but does not authorize a protocol transition.

The system combines these boundaries in order: canonical request, actor signature, deterministic execution, Merkle inclusion, consensus finality, role verification, local atomic persistence, and external checkpoint advancement.

## Availability

Thunderbolt requires a responsive committee threshold, Ledger quorum, Bitcoin backend, and checkpoint providers. If one is unavailable, role services stop advancing rather than accepting weaker evidence.

Admission, proposal scanning, proof work, history replay, and query serialization are bounded. Operator deployments must also configure CometBFT mempool, fee, rate, connection, and block limits to match the application profile.

## Privacy

Thunderbolt keeps participant secrets out of the Ledger, but the base protocol does not promise transaction unlinkability. Operators should assume that public channel identifiers, timing, Ledger entries, and Bitcoin funding and settlement transactions can be correlated.

## Exclusions

The base release transfers ownership of a whole locked UTXO. Routed Lightning payments, unilateral-exit overlays, off-chain splitting, host compromise, and denial of service beyond the documented quorum and resource assumptions are outside this threat model.
