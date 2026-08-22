# API and event contract

Bitcoin Thunderbolt `v1.0.0-rc.1` exposes a loopback JSON API through `thunderboltd` and a thin client named `thunderbolt-cli`. The current server is a reference Thunderbolt Ledger. Holder, committee, Bitcoin settlement, remote administration, metrics, and a signed protocol transport remain target work.

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
| `POST /v1/channels/{id}/events` | `write` | Submit one development-gated Ledger entry |
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

The safe default server has no production verifier and rejects every submitted event with `verification_unavailable`. A development regtest demonstration must start with:

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

`thunderbolt-storage` applies the reducer and commits the immutable entry plus its channel snapshot in one SQLite transaction. An exact repeat of the same per-channel idempotency key and canonical entry returns the original committed result with `replayed = true`. Reusing the key for different content is rejected.

## Current public wire messages

`thunderbolt-wire` provides bounded JSON encoding for the public Invoice, Transfer, threshold-share, and message types. It has no wire representation for witnesses, Holder secrets, refresh scalars, committee shares, decryption keys, or signing material.

The RC codec fixes Paillier values at 2048 bits. The accepted paper evaluates 3072-bit Paillier. The project must reconcile that parameter and version the encoding before mainnet approval.

## Target full protocol contract

The production event envelope needs fields equivalent to:

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
