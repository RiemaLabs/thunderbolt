# Configuration

Thunderbolt uses one TOML file per Ledger, Holder, or committee process. The file contains public deployment policy and references to credentials. It must not contain private keys, passwords, shares, tokens, or signing nonces.

Example files are available in [`crates/thunderbolt-runtime-config/examples`](../crates/thunderbolt-runtime-config/examples).

## File requirements

The daemon requires:

- an absolute configuration path
- an owner-only regular file
- owner-only parent directories
- no symlink or hard-link aliases
- absolute paths for every referenced file and database
- exact SHA-256 digests for public manifests

Run the daemon and CLI as the same operating-system user. The CLI revalidates the same file before connecting to the local control socket.

## Roles

Set `role` to `ledger`, `holder`, or `committee`. Each role has a closed schema and rejects unknown fields.

Common sections are:

| Section | Purpose |
| --- | --- |
| `identity` | Network, Ledger chain, deployment, committee, suite, and policy identity |
| `capabilities` | Deployment, signing, and Paillier capability selection |
| `paths` | Databases, vaults, credential references, manifests, and control socket |
| `control` | Local frame, concurrency, memory, deadline, and shutdown limits |
| `bitcoin` | Bitcoin Core endpoint, cookie reference, limits, and retry policy |

The Ledger also configures `application`, `abci`, and `ledger_profiles`. Holder and committee processes configure `comet` plus their role-specific service limits.

## Public manifests

The deployment pins the committee descriptor, proof suite, runtime profile, CometBFT trust policy, and external checkpoint providers. The configuration records the expected digest and identity of each manifest. The runtime reopens and rehashes them immediately before handing the configuration to a role service.

A checkpoint-provider manifest describes the provider. It is not checkpoint state and does not make a local file an independent rollback floor. The runtime must receive the matching provider capability separately.

## Secret references

Secret fields are file references only. Examples include the Bitcoin Core cookie, vault password, and mutual-TLS client key. Keep these files outside source control and restrict them to the process account.

The redacted configuration returned by the CLI does not print paths, network endpoints, or credential contents.

## Network profiles

Regtest and signet are supported during the release candidate. Every process in one deployment must use the same Bitcoin genesis hash, Ledger chain, deployment identifier, committee descriptor, proof suite, and finality policy.

Literal loopback HTTP is accepted only for regtest CometBFT profiles. Remote CometBFT peers require HTTPS, pinned CA certificates, a pinned node identity and SPKI binding, and a client certificate.

## Validate before start

```bash
thunderboltd --config /var/lib/thunderbolt/runtime.toml check
```

The command parses the closed schema, validates policy relationships and filesystem references, derives the role identity, and prints a redacted summary. It does not start a service or modify role databases.

After provisioning, start with:

```bash
thunderboltd --config /var/lib/thunderbolt/runtime.toml start
```

Treat any reported blocker as a deployment error to resolve rather than a value to bypass.
