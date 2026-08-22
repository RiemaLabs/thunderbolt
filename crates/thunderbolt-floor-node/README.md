# Bitcoin Thunderbolt Floor node

`thunderbolt-floor-node` runs the independent rollback-floor application behind
CometBFT. It reads one owner-only TOML file plus SHA-256-pinned public registry
and validator manifests.

The binary has three commands:

```text
thunderbolt-floor-node --config /var/lib/thunderbolt-floor/config/node.toml check
thunderbolt-floor-node --config /var/lib/thunderbolt-floor/config/node.toml genesis
thunderbolt-floor-node --config /var/lib/thunderbolt-floor/config/node.toml start
```

`check` validates without creating or changing the database. `genesis` writes a
complete compact CometBFT genesis document to standard output. `start` serves
ABCI on an owner-only Unix socket or a numeric loopback TCP address.

The registry manifest contains public vault identities and their BIP340
operator keys. The validator manifest contains an ordered Ed25519 validator set
and positive voting powers. Both files use compact canonical JSON with one
trailing newline. Put their lowercase SHA-256 digests in the TOML configuration.

Mainnet identities and remote listeners are rejected.

## Configuration

Run the Floor node and its colocated CometBFT process as the dedicated
`thunderbolt-floor` operating-system account. Do not reuse the UID of a Holder,
Committee member, or Thunderbolt Ledger process. Create the configuration,
manifest, database, and socket directories as `thunderbolt-floor`. Directories
must be mode `0700`; the TOML and manifest files must be mode `0600` and have
one hard link.

```toml
format = "bitcoin-thunderbolt-floor-node"
chain_id = "thunderbolt-floor-regtest-1"
genesis_time = "2026-01-01T00:00:00Z"
network = "regtest"
database_path = "/var/lib/thunderbolt-floor/data/floor.sqlite3"

[registry_manifest]
path = "/var/lib/thunderbolt-floor/config/registry.json"
sha256 = "replace-with-lowercase-sha256"

[validator_manifest]
path = "/var/lib/thunderbolt-floor/config/validators.json"
sha256 = "replace-with-lowercase-sha256"

[server.endpoint]
kind = "unix"
path = "/run/thunderbolt-floor/abci.sock"

[server.limits]
max_connections = 16
max_concurrent_handlers = 8

[server.deadlines_ms]
accept_poll = 5
idle = 30000
header = 2000
read = 2000
frame = 15000
decode = 5000
write = 15000
handler = 60000
shutdown_grace = 75000
```

The registry JSON has this compact shape. Entries must already be ordered by
their derived vault-identity digest.

```json
{"format":"bitcoin-thunderbolt-floor-registry","entries":[{"network":"regtest","role":"committee_member","node_id":"<32-byte-lowercase-hex>","deployment_id":"<32-byte-lowercase-hex>","committee_epoch":1,"committee_descriptor":"<32-byte-lowercase-hex>","operator_key":"<BIP340-x-only-key-hex>"}]}
```

The validator JSON contains the exact CometBFT Ed25519 keys and positive voting
powers. Order must match CometBFT's canonical power-then-address order.

```json
{"format":"bitcoin-thunderbolt-floor-validators","validators":[{"public_key":"<32-byte-lowercase-hex>","power":10}]}
```

Both JSON files end with one newline. Compute their digests with
`shasum -a 256`. Then validate and create the CometBFT genesis document:

```bash
thunderbolt-floor-node --config /var/lib/thunderbolt-floor/config/node.toml check
umask 077
set -C
thunderbolt-floor-node --config /var/lib/thunderbolt-floor/config/node.toml genesis > genesis.json
```

Every validator uses the same genesis document, registry manifest, validator
manifest, and Floor node configuration. Start CometBFT with its `proxy_app`
pointing to the configured local ABCI endpoint.
