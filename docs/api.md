# API

Thunderbolt separates local operator control from protocol and consensus traffic. The default CLI exposes a fixed local control surface. Role services use typed Rust interfaces for Ledger, finality, Bitcoin, and rollback-floor operations.

## Local control

`thunderboltd` listens on the owner-only Unix socket configured for the process. Frames are length-bounded and correlated by a 128-bit request identifier. The server accepts only these methods:

| CLI command | Control method | Result |
| --- | --- | --- |
| `status` | `runtime.status` | Role, lifecycle, liveness, readiness, and fault code |
| `blockers` | `runtime.blockers` | Stable readiness blockers |
| `redacted-config` | `runtime.redacted_config` | Secret-free deployment identity and policy summary |
| `drain` | `runtime.drain` | Stop accepting role work and finish accepted work |
| `stop` | `runtime.stop` | Cleanly stop the runtime |

Every method takes an empty payload. There is no generic method call, raw JSON payload, protocol submission, database mutation, or start command on the local control socket.

The runtime stores a bounded mapping from request identifier to operation and result. Retrying an identical request returns the original result; reusing the identifier for another operation returns a conflict.

## Ledger proposals

A Ledger proposal binds:

- Ledger chain and complete channel identity
- sequence and predecessor
- actor role, public key, and derived participant identifier
- request digest and event kind
- canonical bounded event bytes
- BIP340 signature

The actor signs the proposal body. Clients cannot attach their own verification result or finality claim.

## Ledger queries

The Ledger query codec has fixed constructors for:

- application and channel status
- exact request status
- exact blocks and compact entry proofs
- bounded contiguous execution ranges, including empty blocks
- first finalized location of a stable entry

Responses are decoded against the exact request. Public semantic types do not offer an unrestricted deserialization path around request correlation and outer byte limits.

Query results describe deterministic execution. A role service obtains authority only after the CometBFT client verifies the matching header, application hash, entry proof, and configured trust policy.

## Broadcasts

The authenticated CometBFT client performs one proposal broadcast after checking the remote node status and identity. An accepted response means the transaction entered the peer's admission path; it does not mean the entry is finalized.

If the write outcome is uncertain, the client returns `AmbiguousWrite` with the deterministic proposal hash. Callers reconcile through exact request and finalized-history queries rather than sending a different request.

## Role capabilities

Holder and committee services receive private in-process capabilities after finality verification. Serializable historical references contain no authority and must be revalidated against the durable trust coordinator before use.

Committee ingestion consumes whole contiguous finalized blocks. It persists compact block commitments, exact entries, Merkle proofs, and its cursor, not raw consensus receipts or full block copies.

## Rollback floor

The floor accepts an actor-signed compare-and-swap request tied to the exact target height and prior application hash. State and result proofs must be checked against the exact committed block and configured genesis. Local history anchors support bounded compaction but do not replace external consensus finality.

## Size limits

The protocol uses coordinated limits across wire messages, events, proposals, blocks, queries, and snapshots. The compiled consensus profile commits all consensus-affecting values so validators with different resource policy cannot join the same deployment.

Network adapters must enforce their raw frame or HTTP body limit before decoding JSON, protobuf, base64, or nested proof values.
