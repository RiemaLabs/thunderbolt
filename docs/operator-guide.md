# Operator guide

Thunderbolt runs one process for each Ledger validator, Holder, and committee member. Each process owns one configuration, one local control socket, and its own durable state.

## Build

```bash
cargo build --locked --release \
  --package thunderboltd \
  --package thunderbolt-cli
```

Install both binaries from the same source commit. Keep the release checksum and software bill of materials with the installation record.

## Provision a process

1. Create a dedicated operating-system account.
2. Create owner-only data and control directories.
3. Provision the role database, encrypted vault, and credential files.
4. Install the committee, proof-suite, runtime-profile, and trust manifests.
5. Configure Bitcoin Core and CometBFT peers for the deployment.
6. Provision independent checkpoint providers for participant and light-client state.
7. Copy the matching example TOML and replace every placeholder path and digest.
8. Set the configuration file to owner-only access.

Use a separate host or failure domain for each committee share where possible. Never copy one committee vault to create another member.

## Validate

```bash
thunderboltd --config /var/lib/thunderbolt/runtime.toml check
```

Review the redacted deployment identity and resolve all file, digest, policy, network, and capability errors before start.

## Start

```bash
thunderboltd --config /var/lib/thunderbolt/runtime.toml start
```

The daemon stays in the foreground and emits structured JSON logs by default. Use `--log-format pretty` for local regtest work.

The process acquires an identity-bound lock and records an unclean restart marker until shutdown completes. A second process cannot use the same identity or data path.

## Control

Run the CLI as the daemon user:

```bash
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml status
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml blockers
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml redacted-config
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml drain
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml stop
```

The CLI connects only to the configured Unix socket. Each command carries a random request identifier. If a response is uncertain, retry the same command with the same identifier so the daemon can return the original result.

`drain` stops new role work and lets accepted work finish. `stop` performs a clean shutdown after the correlated reply is written.

## Restart and recovery

After a clean stop, start the process normally. After a crash:

1. Preserve the data directory and logs.
2. Start the daemon without bypassing the dirty marker.
3. Inspect `status` and `blockers`.
4. Reconcile the role database, external checkpoint, finalized Ledger cursor, and pending outbox.
5. Clear the recovery condition only through the documented role recovery path.

Do not delete the marker, rewind SQLite, or copy a newer vault over an older process identity.

The control server can remove its own stale socket after verifying ownership, inode, link count, and that no server is accepting connections. It never replaces an active socket.

## Backup

Back up the role database, encrypted vault, public manifests, and the exact external checkpoint identity together. Encrypt backup media and label it with the network, deployment, process identity, source commit, and last finalized height.

Test restore on an isolated host. Reauthenticate the checkpoint and replay finalized history before enabling mutations.

## Monitoring

Monitor:

- process liveness and readiness blockers
- Ledger and role cursor lag
- committee quorum and member availability
- outbox age and ambiguous submissions
- Bitcoin Core height, confirmations, and reorganizations
- database latency, WAL growth, checkpoint age, and backup age

Logs must not contain private keys, shares, vault passwords, tokens, decrypted records, or signing nonces.

## Shutdown

Prefer `thunderbolt-cli stop`. `SIGINT` and `SIGTERM` also trigger the same clean shutdown path. Wait for the process to exit and the control socket to disappear before moving or restoring its data.
