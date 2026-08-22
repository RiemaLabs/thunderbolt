# Operator guide

Bitcoin Thunderbolt `v1.0.0-rc.1` runs a reference Thunderbolt Ledger for development and regtest. Mainnet is disabled. The repository includes Holder, committee, Trusted Verifier, Keystore, and Bitcoin Core libraries. The node library can inject the Trusted Verifier, but the shipped daemon does not configure it or run the other role libraries. It also does not expose metrics.

## What runs in this RC

`thunderboltd`
: A Ledger-role daemon with a loopback JSON API, deterministic channel reducer, SQLite event log, integrity checking, and verified manual backup.

`thunderbolt-cli`
: A stateless client for health, node information, redacted configuration, channel and event reads, development event submission, database administration, and graceful stop.

The daemon requires `[node].role = "ledger"`. It refuses Holder and committee roles. Those roles describe the protocol and remain target runtime work.

## What is library-only

Building the workspace also builds these non-executable components:

| Crate | What it provides | What operators cannot do yet |
| --- | --- | --- |
| `thunderbolt-ledger` | BIP340 signed version 2 proposals, executed blocks, application hashes, and Merkle proofs | Run consensus, ABCI, persistent version 2 state, or obtain finality |
| `thunderbolt-protocol` v2 | Concurrent bounded Invoices, consensus time, exact selected Transfer, and ordered Finalize rules | Activate version 2 in the daemon or verify production Open and Finalize proofs |
| `thunderbolt-holder` | Local Holder and Recipient state plus a concrete fenced Keystore adapter | Start a Holder daemon, obtain trusted acknowledgements, or run outboxes and Ledger cursors |
| `thunderbolt-committee` | One-share updates plus a concrete fenced Keystore adapter | Start a committee daemon, verify a concrete quorum receipt, run DKG, or produce and aggregate FROST shares |
| `thunderbolt-verifier` | Trusted Invoice and Transfer verification plus node injection API | Configure a production verifier in `thunderboltd`, or verify Open and Finalize |
| `thunderbolt-keystore` | Encrypted transactional multi-record vault, revision floors, nonce tombstones, and restricted restore | Unlock or manage participant secrets through the daemon or CLI, or restore committee signing state |
| `thunderbolt-bitcoin` | Validated Bitcoin Core RPC, chain tracking, and transaction policy checks | Connect the daemon to Bitcoin Core, fund a channel, or complete settlement |

These libraries are implementation building blocks. Installing them does not create a Thunderbolt network or complete the lifecycle described in the paper.

## Build

Use the pinned Rust toolchain:

```bash
cargo build --locked --release
cargo test --workspace --all-features --locked --lib --bins --tests
```

The first command builds the default release members and excludes research-only settlement and single-process committee code. The full workspace test command enables those features deliberately for regression coverage. Release packaging builds only `thunderboltd` and `thunderbolt-cli`.

Inspect the exact command surface from the built commit:

```bash
./target/release/thunderboltd --help
./target/release/thunderbolt-cli --help
```

## Initialize a local node

`init` creates a regtest and development configuration without overwriting an existing configuration or token:

```bash
./target/release/thunderboltd \
  --config ./thunderbolt.toml \
  init --data-dir ./data --node-id thunderbolt-node
```

It creates:

```text
./thunderbolt.toml                 configuration
./data/thunderbolt.sqlite3        database after first start
./data/auth/operator.token        generated bearer token
./data/backups/                   manual backup destination
./data/logs/                      reserved log directory
./data/thunderboltd.sock          reserved path, not a live socket in this RC
```

On Unix, the directories use mode `0700` and the token uses `0600`. The token identifier is the value passed to `--node-id`. `init` fails if either the configuration or token path already exists.

## Check before start

```bash
./target/release/thunderboltd --config ./thunderbolt.toml check
```

`check` validates the configuration, credentials, runtime safety rules, and existing database integrity. Its JSON output reports whether the database exists and confirms that mainnet is disabled.

## Start

```bash
./target/release/thunderboltd \
  --config ./thunderbolt.toml \
  start --log-format pretty
```

JSON logs are also available:

```bash
./target/release/thunderboltd \
  --config ./thunderbolt.toml \
  start --log-format json
```

The daemon listens on `[admin].bind_address` and `[admin].port`, which default to `127.0.0.1:19736`. This is loopback HTTP. The runtime refuses a non-loopback address, remote HTTP, built-in TLS, mainnet, and any role other than Ledger.

`paths.socket_path` is reserved for a future local control transport. The RC does not listen on a Unix socket.

## Use the CLI

The CLI reads its endpoint and bearer-token path from the configuration:

```bash
./target/release/thunderbolt-cli --config ./thunderbolt.toml health
./target/release/thunderbolt-cli --config ./thunderbolt.toml health --ready
./target/release/thunderbolt-cli --config ./thunderbolt.toml getinfo
./target/release/thunderbolt-cli --config ./thunderbolt.toml config show
```

Health routes are unauthenticated so a local supervisor can test liveness and readiness. Every other `/v1` route requires a bearer token.

Channel and event reads:

```bash
./target/release/thunderbolt-cli --config ./thunderbolt.toml channel list
./target/release/thunderbolt-cli --config ./thunderbolt.toml channel get <channel-id>
./target/release/thunderbolt-cli --config ./thunderbolt.toml \
  channel events <channel-id> --after-sequence 0 --limit 100
./target/release/thunderbolt-cli --config ./thunderbolt.toml \
  channel event <channel-id> <sequence>
```

Database administration:

```bash
./target/release/thunderbolt-cli --config ./thunderbolt.toml database integrity
./target/release/thunderbolt-cli --config ./thunderbolt.toml database backup
./target/release/thunderbolt-cli --config ./thunderbolt.toml \
  database backup --filename operator-checkpoint.sqlite3
```

The backup command creates a no-clobber SQLite backup in `[backup].directory` and verifies it before returning. The daemon does not encrypt the backup in this RC. Protect the directory with filesystem or encrypted-volume controls.

Optional CLI overrides are `--endpoint`, `--token-file`, and `--timeout-seconds`. Do not put a bearer-token value in a command argument.

## Development event submission

The safe default daemon has no production proof verifier, so it rejects event submission. The node library's `bind_with_verifier` API is for an embedding runtime and has no TOML or CLI equivalent. Even an injected verifier supports only Invoice and Transfer; Open and Finalize fail closed.

To exercise the state machine on development regtest, restart it with the explicit demo flag:

```bash
./target/release/thunderboltd \
  --config ./thunderbolt.toml \
  start --log-format pretty \
  --development-allow-unverified-demo-events
```

The flag is rejected outside `environment = "development"` and `network = "regtest"`. In demo mode, the server still rejects verification evidence supplied by a client. It inserts synthetic evidence labeled `development-unverified-demo` before applying the reducer.

Submit a `LedgerEntry` JSON file:

```bash
./target/release/thunderbolt-cli --config ./thunderbolt.toml \
  submit event --file ./entry.json
```

Omit `--file` or use `--file -` to read JSON from standard input.

Event submission requires `write` scope. The authenticated token identifier must exactly match `LedgerEntry.actor.participant_id`, and the reducer checks the actor's event-specific role. An `admin` token does not bypass the identity match. The token created by `init` uses the configured node identifier, so distinct participants need separate protected token files and matching token identifiers.

Demo events are not proof-verified protocol messages. Do not carry a demo database into a future production deployment.

## Container regtest demo

The Compose profile starts the Ledger with the unverified-demo flag. It does not run Bitcoin Core, a Holder, or committee members.

```bash
make regtest-up
```

Check readiness inside the container:

```bash
docker compose --file deploy/regtest/compose.yaml exec -T thunderboltd \
  thunderbolt-cli \
  --config /etc/bitcoin-thunderbolt/thunderbolt.toml \
  health --ready
```

The equivalent Make target is `make regtest-status`. Stop the profile with:

```bash
make regtest-down
```

The Compose files are [`compose.yaml`](../deploy/regtest/compose.yaml) and [`thunderbolt.toml`](../deploy/regtest/thunderbolt.toml).

## Participant vault recovery

`thunderbolt-keystore` is not used by this daemon. Concrete Holder and committee adapters exist, but future role operators must supply an independent authenticated `RollbackFloorStore` and preserve these rules:

- multi-record updates use one authenticated revision and one transaction identifier;
- a consumed signing nonce becomes a permanent tombstone;
- the external checkpoint contains both revision and encrypted-state digest;
- every secret read and output is fenced until exact checkpoint CAS succeeds;
- a sibling file beside the vault is not a production checkpoint store;
- exact anchored backups can be restored to an empty destination;
- receipt pruning requires independent durable request history, and nonce tombstones are never pruned.

An old or equal-revision forked vault file can authenticate successfully. Without the exact external checkpoint, authentication alone does not detect rollback while the process is stopped. The repository has no automatic recovery for a process killed after local persistence but before checkpoint advancement.

## Release test evidence

The Bitcoin backend passed the official Bitcoin Core v31.1.0 live gate, including release-file verification, isolated regtest, the exact 100-confirmation coinbase boundary, a one-block disconnect and distinct replacement, graceful same-datadir restart, and a full rerun after restart. The test is ignored and environment-gated in the repository, so CI does not reproduce it automatically. See [Testing](testing.md) for the exact evidence boundary.

## systemd assets

The repository includes:

- [`thunderboltd.service`](../deploy/systemd/thunderboltd.service)
- [`thunderbolt.sysusers`](../deploy/systemd/thunderbolt.sysusers)
- [`thunderbolt.toml`](../deploy/systemd/thunderbolt.toml)

The service runs as an unprivileged `thunderbolt` user, loads the bearer token through a systemd credential, checks the configuration before start, and applies service sandboxing. The example uses signet and starts without the unverified-demo flag, so event submission stays disabled until a real verifier exists.

Review paths, the node identifier, the token identifier, and host support for each sandbox directive before installation. These assets operate the reference Ledger only.

## Health and shutdown

The HTTP health paths are:

```text
/v1/health/live
/v1/health/ready
```

Compatibility aliases `/live` and `/ready` are also available. The daemon marks itself unready before an authenticated stop:

```bash
./target/release/thunderbolt-cli --config ./thunderbolt.toml stop
```

`SIGINT` and `SIGTERM` also begin graceful shutdown. The daemon drains requests up to the configured shutdown timeout.

## Current limits

- Mainnet is rejected by configuration, daemon, and CLI checks.
- Only the Ledger server role runs.
- The control transport is loopback HTTP, not the reserved Unix socket.
- Remote control and built-in TLS are rejected.
- The daemon runs version 1 and has no configured production verifier. The node injection API verifies only version 1 Invoice and Transfer.
- The standalone version 2 Ledger and reducer are not connected to the daemon, SQLite service, ABCI, or CometBFT.
- Open, Finalize, actor signatures, Bitcoin policy, and concrete quorum receipts are not connected to event submission.
- The Holder and committee Keystore adapters exist, but no role daemon, outbox, Ledger cursor, production checkpoint store, or Bitcoin coordination uses them.
- Metrics settings are parsed but no metrics endpoint runs.
- Backups are verified but not encrypted by the daemon.
- The Compose profile is a Ledger and storage demonstration, not a Bitcoin regtest network.
- The wire codec uses 2048-bit Paillier values, while the accepted paper evaluates 3072-bit Paillier.
- Open has no reviewed DKG or provisioning ceremony. Finalize has no `R_own` proof or combined-key Holder plus FROST signing path under `P`.
- Version 2 signed proposals and concurrent-Invoice reduction exist only as standalone libraries. Executed blocks are not finality receipts.
- Holder and committee retained histories need compaction or epoch rotation for long-lived operation.

Role processes, participant vault adapters, outboxes, Ledger cursors, Bitcoin settlement, threshold signing, metrics, and a production Ledger fault model remain release work. See [Production roadmap](roadmap.md).
