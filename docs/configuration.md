# Configuration

Bitcoin Thunderbolt `v1.0.0-rc.1` uses a versioned TOML configuration with safe defaults and strict rejection of unknown fields. The implementation lives in `thunderbolt-config`; its commented example is [`sample-config.toml`](../crates/thunderbolt-config/sample-config.toml).

The RC is not approved for mainnet. A configuration that parses successfully is not an operator approval or proof that the full protocol runtime is available.

## Resolution order

The configuration library resolves settings in this order:

1. built-in defaults
2. one TOML file
3. supported `THUNDERBOLT_` environment overrides

Later sources replace earlier values. Nested environment names use a double underscore, such as `THUNDERBOLT_ADMIN__PORT=29736`. Short aliases include `THUNDERBOLT_ROLE`, `THUNDERBOLT_NETWORK`, `THUNDERBOLT_DATA_DIR`, and `THUNDERBOLT_LEDGER_ENDPOINT`.

Environment values are useful for non-secret deployment settings, but process environments often leak through diagnostics and service managers. Passwords, private keys, committee shares, seeds, API credentials, and bearer tokens do not belong in TOML, flags, or environment variables.

## Minimal development configuration

This example is for a local reference Ledger on regtest:

```toml
config_version = 1

[node]
id = "ledger-dev-01"
role = "ledger"
listen_address = "127.0.0.1"
listen_port = 19735

[deployment]
environment = "development"
network = "regtest"

[paths]
data_dir = "./data"
log_dir = "./data/logs"
database_path = "./data/thunderbolt.sqlite3"
socket_path = "./data/thunderboltd.sock"

[committee]
members = 3
signing_threshold = 2

[admin]
enabled = true
bind_address = "127.0.0.1"
port = 19736
remote_http = false

[ledger]
endpoint = "http://127.0.0.1:19736/"

[auth]
enabled = true

[[auth.tokens]]
id = "ledger-dev-01"
token_file = "./data/auth/operator.token"
scopes = ["admin"]
```

The configuration library fills omitted limit, metrics, backup, TLS, and development fields from defaults. Inspect the generated effective configuration before use.

## Sections

### `node`

`node.id`
: Public process identifier containing 1 to 64 ASCII letters, digits, `.`, `_`, or `-`.

`node.role`
: `holder`, `committee`, or `ledger` at the configuration layer. `thunderboltd start` in this RC requires `ledger` and rejects the other roles.

`node.listen_address` and `node.listen_port`
: Reserved listener for future protocol traffic. It must not overlap the administrative or metrics endpoint. The current daemon serves only the administrative loopback address and port.

### `deployment`

`deployment.environment`
: `development`, `staging`, or `production`. Production requires absolute data and credential paths and forbids development escape flags.

`deployment.network`
: `regtest`, `signet`, `testnet`, or `mainnet`. The `v1.0.0-rc.1` validator rejects mainnet in every environment. Regtest is the documented development profile unless a release note explicitly supports another test network.

### `paths`

`paths.data_dir`, `log_dir`, `database_path`, and `socket_path` locate local state. Production paths must be absolute, must not contain `..`, and must remain inside the configured data directory where required. The data directory cannot be the filesystem root.

The Unix socket path is reserved for the target local control interface. The current daemon does not create or listen on that socket. It uses the loopback administrative HTTP listener.

### `committee`

`committee.members` accepts 1 through 1024 members. `committee.signing_threshold` must be at least 1 and cannot exceed the member count. These values describe expected topology but do not contain any share.

A production node must also verify membership, threshold, and epoch against a signed committee descriptor. Local TOML cannot change committee membership on its own.

### `admin` and `admin.tls`

The administrative HTTP listener binds to loopback by default, on port `19736`. The `v1.0.0-rc.1` runtime rejects non-loopback binding, `remote_http = true`, and built-in TLS. Authentication remains separate and should stay enabled.

### `ledger`

`ledger.endpoint` is an absolute HTTP or HTTPS URL without inline credentials, query text, or a fragment. Plain HTTP is accepted only on loopback unless an explicit development escape flag is set. Production deployments should use HTTPS.

`ledger.auth_token_file` refers to a protected credential file. The endpoint URL must never contain a username, password, or token.

### `limits`

The implemented limits cover request headers and bodies, concurrent requests, connection timeout, request timeout, idle timeout, and graceful shutdown timeout. The library validates bounded values before startup.

Keep proof-verification concurrency below the host's safe CPU and memory capacity. A maximum accepted body size is not permission to allocate that amount repeatedly without a queue bound.

### `metrics`

The configuration schema reserves metrics settings, but `v1.0.0-rc.1` does not expose a metrics endpoint. Health and readiness HTTP routes are available. Metrics remain target work.

### `backup`

Backup settings define the directory, interval, retention count, verification after write, and optional encryption-key file. The current runtime implements an authenticated manual `database backup` request and verifies the SQLite backup before returning. It does not schedule backups, apply retention, or encrypt the file. Those settings are reserved for later runtime work.

### `auth` and token files

Each configured token has an identifier, a file, and one or more scopes:

- `read`
- `write`
- `operator`
- `admin`

Scopes form an increasing privilege hierarchy. Token files are loaded separately from TOML. On Unix they must be regular, non-symlink files with mode `0400` or `0600`. Tokens contain 32 through 512 visible ASCII bytes. The loader compares fixed-size values in constant time and does not expose token contents through debug output.

Generate tokens with a CSPRNG. Never reuse a repository example, test value, or token from another node.

For event submission, the token must include `write` scope and its `id` must exactly match `LedgerEntry.actor.participant_id`. Higher scope does not permit actor impersonation. `thunderboltd init` creates one `admin` token whose identifier matches `--node-id`; distinct demo participants need separate token files and matching identifiers.

### `development`

Development flags can allow insecure Ledger HTTP, unauthenticated administration, invalid TLS certificates, or ephemeral storage in isolated tests. Validation forbids all of them in production and on mainnet.

Do not use a development escape flag to work around a deployment error. Fix the trust root, listener, credential, or filesystem problem.

## Redacted output

The configuration library can render the fully merged configuration with secret-bearing file locations replaced. Inspect it with `thunderbolt-cli --config PATH config show`. Include it in a bug report only after checking it again for operator-identifying data.

Redaction removes configured secret paths, not arbitrary secrets placed in the wrong fields. Keep secrets out of the source configuration from the start.

## Validation checklist

Before startup, confirm:

- the software release and protocol version match the intended deployment
- the Bitcoin network matches the Ledger, database, and committee context
- the node role matches the process you intend to run
- `node.role` is `ledger`, listeners do not overlap, and administrative access stays on loopback
- authentication is enabled and token files have owner-only permissions
- no credential appears in TOML, URL, flags, or environment
- production paths are absolute and owned by the daemon user
- committee member count and threshold match the signed descriptor
- manual backup verification succeeds and the backup directory is protected
- every development escape flag is false
- the RC is running on regtest, not mainnet

Never commit an operator's real configuration. New repository examples should use local addresses, reserved example hosts, and dummy identifiers only.
