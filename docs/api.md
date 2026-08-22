# API and event contract

Bitcoin Thunderbolt `v1.0.0-rc.1` exposes a loopback JSON API through `thunderboltd` and a thin client named `thunderbolt-cli`. The current server is a reference Thunderbolt Ledger. The node library has a transaction-scoped Trusted Verifier injection point for Invoice and Transfer, but the shipped daemon does not configure it and remains Ledger-only.

## Control transport

The daemon listens on `[admin].bind_address` and `[admin].port`, which default to `127.0.0.1:19736`. Runtime validation rejects non-loopback binding, remote HTTP, and built-in TLS. `paths.socket_path` is reserved but not listened on.

Health routes are unauthenticated. Every other `/v1` route requires one bearer token from a configured owner-only file.

## CLI

Global syntax:

```text
thunderbolt-cli \
  --config PATH \
  [--endpoint URL] \
  [--token-file PATH] \
  [--timeout-seconds N] \
  <command>
```

Implemented commands:

| Command | Purpose |
| --- | --- |
| `health` | Query process liveness |
| `health --ready` | Query readiness |
| `getinfo` | Show public node identity, versions, role, network, safety mode, and uptime |
| `config show` | Show effective configuration with secret-bearing paths redacted |
| `channel get ID` | Get one materialized channel snapshot |
| `channel list [--after ID] [--limit N]` | List channel snapshots with a stable cursor |
| `channel events ID [--after-sequence N] [--limit N]` | List immutable Ledger entries for a channel |
| `channel event ID SEQ` | Get one immutable Ledger entry |
| `submit event [--file FILE]` | Submit a `LedgerEntry` JSON document; standard input is used when the file is omitted or `-` |
| `database integrity` | Check SQLite integrity, event indexes, every hash chain, reducer replay, and snapshots |
| `database backup [--filename NAME]` | Create a no-clobber, verified SQLite backup |
| `stop` | Mark the daemon unready, drain requests, and stop |

The CLI reads `[ledger].endpoint` and `[ledger].auth_token_file` unless a global override is supplied. Do not put a token value in a command argument.

## HTTP routes

| Method and path | Scope | Behavior |
| --- | --- | --- |
| `GET /v1/health/live` | public | Return process liveness |
| `GET /v1/health/ready` | public | Return readiness or HTTP 503 |
| `GET /v1/info` | `read` | Return public runtime metadata |
| `GET /v1/config` | `read` | Return redacted effective configuration |
| `GET /v1/channels` | `read` | List channel snapshots |
| `GET /v1/channels/{id}` | `read` | Get one channel snapshot |
| `GET /v1/channels/{id}/events` | `read` | List channel entries |
| `GET /v1/channels/{id}/events/{sequence}` | `read` | Get one entry |
| `POST /v1/channels/{id}/events` | `write` | Submit one evidence-free proposal; the shipped daemon requires development demo mode because it has no Trusted Verifier |
| `POST /v1/database/integrity` | `operator` | Run the full storage integrity check |
| `POST /v1/database/backup` | `admin` | Create and verify a manual backup |
| `POST /v1/admin/stop` | `admin` | Begin graceful stop |

Liveness and readiness aliases also exist at `/live`, `/ready`, `/health/live`, and `/health/ready`.

The daemon bounds headers, request bodies, concurrency, database workers, pagination, and request time. API errors use a stable JSON code and a short message without an internal stack trace.

## Authorization

Scopes increase from `read` to `write`, `operator`, and `admin`. A higher scope includes the lower scopes.

Event submission has an extra identity rule: the authenticated token `id` must exactly match `LedgerEntry.actor.participant_id`. An operator or administrator token does not bypass that check. The reducer then checks the actor's role for the event type.

`thunderboltd init` creates one token with `admin` scope and an identifier equal to `--node-id`. A multi-participant demonstration needs one protected token file per distinct participant, with each configured token identifier matching that participant's Ledger actor identifier.

## Event submission safety mode

The safe default daemon has no production verifier and rejects every submitted event with `verification_unavailable`. The node library can inject `TrustedVerifier` through `NodeServer::bind_with_verifier` or `from_listener_with_verifier`, but no daemon configuration or CLI option selects those constructors. A development regtest demonstration must start with:

```bash
thunderboltd --config PATH start \
  --development-allow-unverified-demo-events
```

The flag is rejected outside development regtest. The server also rejects any verification evidence supplied by the client. In demo mode it inserts synthetic attestations labeled `development-unverified-demo` before calling the reducer.

Synthetic evidence is not proof verification. A demo event or database must not be represented as a valid protocol execution or carried into a later production deployment.

## Implemented Ledger entry

`thunderbolt-protocol` defines a version-one `LedgerEntry`:

```text
protocol_version
channel_id
sequence
previous_entry_hash
idempotency_key
actor
occurred_at_ms
event
```

Implemented event payloads are `Open`, `Invoice`, `Transfer`, and `Finalize`. Entries use a versioned, domain-separated canonical hash independent of JSON field order. Identifiers and artifacts are bounded.

The reducer checks lifecycle, sequence, previous hash, actor role, channel-lifetime invoice uniqueness, bounds, timestamps, and required verification-attestation kinds. It does not verify signatures, zero-knowledge proofs, Bitcoin transactions, or committee quorums.

`thunderbolt-storage` provides `append_verified_proposal` for service writes. It rejects client-supplied evidence, acquires the SQLite writer lock, deduplicates the evidence-free proposal, loads the authoritative snapshot and pending Invoice, samples trusted Ledger time, and invokes the verifier callback inside that transaction. It then commits the immutable entry, node evidence, channel snapshot, and retry mapping together. Exact retries return the original result without repeating verification. A verifier or persistence failure rolls back every related row.

`append_entry` remains a trusted import and regression API. It accepts an already verified entry and must not be used as the public request path.

## Current public wire messages

`thunderbolt-wire` provides bounded JSON encoding for the public Invoice, Transfer, threshold-share, and message types. It has no wire representation for witnesses, Holder secrets, refresh scalars, committee shares, decryption keys, or signing material.

The RC codec fixes Paillier values at 2048 bits. The accepted paper evaluates 3072-bit Paillier. The project must reconcile that parameter and version the encoding before mainnet approval.

The wire crate also provides `ChannelBindingV2` and `OperationBindingV2`. They define a stable channel `ctx_id` over the protocol suite, Bitcoin network and exact genesis, complete funding outpoint, deployment, committee epoch and descriptor, and anchor parameter suite. Invoice ID and positive Transfer step remain explicit operation inputs. These binding types are not used by the active version 1 envelopes or Ledger events; actor signatures are layered separately by `thunderbolt-ledger`.

`thunderbolt-ledger` layers a separate version 2 contract over that binding. `SignedProposalV2` authenticates the Ledger chain, predecessor, actor-scoped request digest, x-only actor key and derived participant ID, role, event kind, and canonical event bytes with BIP340. `ExecutedBlockV2` commits consensus-supplied height and time, ordered entry metadata, a Merkle root, and the previous application hash.

An executed block or Merkle proof proves deterministic self-consistency, not validator finality. The crate exposes no network, consensus engine, ABCI server, database, quorum certificate, trusted header chain, or durable cross-block request index.

The protocol v2 reducer consumes authenticated executed entries and supports a bounded concurrent Invoice set, exact selected-Invoice Transfer, consensus time, and ordered Finalize. All operation-specific proof checks remain behind abstract `ExternalVerifierV2` hooks.

## Library APIs not exposed by the daemon

The following APIs are available to runtime developers, not to `thunderbolt-cli` users:

- `HolderEngine` creates and records v1 single-committee Invoices and threshold Recipient-share plus VESS packages. `KeystoreSecretVault` is its concrete encrypted adapter with exact-checkpoint fencing and finalized-receipt pruning.
- `CommitteeMemberEngine` verifies the exact Recipient-share, distribution, Transfer, and abstract committed-Ledger binding before a replay-safe update. `KeystoreCommitteeVault` is its concrete fenced adapter. `CommitteeSigner` supplies no FROST implementation or aggregator.
- `TrustedVerifier` verifies Invoice and Transfer artifacts against a `DeploymentContext`, a channel snapshot, and trusted Ledger time. The node can inject it into the atomic append path. It does not verify Open, `R_own`, Finalize, actor signatures, quorum receipts, or Bitcoin state.
- `Vault` encrypts a transactional multi-record participant store. Exact checkpoints contain revision and encrypted-state digest; reads and outputs remain fenced until external checkpoint CAS. Exact anchored backup restore and bounded receipt pruning are available, but no production `RollbackFloorStore` is included.
- `BitcoinCoreClient` validates the selected Bitcoin network before use and provides bounded chain, funding, fee, broadcast, and closing checks. It has no wallet or signing interface.

The current `POST /v1/channels/{id}/events` handler always uses the atomic verified-append path. With an injected Trusted Verifier it can verify Invoice and Transfer. Open and Finalize always fail closed. Because `thunderboltd` starts the node without a verifier, its safe default still rejects all event submission unless the explicit development-regtest demo mode is enabled.

## Protocol v2 runtime gap

The stable binding, signed proposal, executed-block commitment, and reducer are implemented as separate libraries. The runtime and finality layers are not.

The standalone version 2 proposal carries fields equivalent to:

```text
protocol_version
bitcoin_network
ledger_chain_id
channel_id
sequence
step
previous_event_hash
committee_epoch
actor_public_key
request_id
payload_type
payload
actor_signature
```

The signature digest must define a fixed Bitcoin Thunderbolt domain, hash-format version, integer widths, byte order, length encoding, optional-field encoding, and exact field order. Implementations must reject non-canonical values and share checked golden vectors.

Version 2 now has actor-scoped request digests and BIP340 signature validation. It still needs a persistent cross-block request index, ABCI execution and storage, consensus finality verification, concrete operation verifiers, and a durable notification outbox.

The full runtime also needs control operations for wallet initialization and locking, encrypted backup and restore, Open, invoice creation, Transfer, Finalize, event subscriptions, committee update, threshold signing, heartbeat, and resharing. Those operations are not part of the current CLI or HTTP server.

Before committing a production event, the node must verify:

- protocol version, Bitcoin network, Ledger chain, and committee epoch
- actor signature and authorization
- exact sequence and previous event hash
- channel and invoice uniqueness
- real proof, Bitcoin, and committee-quorum evidence
- proof context and canonical encoding
- no competing transfer or Finalize race
- a fully acknowledged Holder state before forwarding or finalization

Any incompatible event encoding or signature change requires a new protocol version, new vectors, migration analysis, and a coordinated activation plan.

The remaining stages are tracked in [Production roadmap](roadmap.md).
