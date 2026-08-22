# Security

Bitcoin Thunderbolt controls Bitcoin ownership credentials and committee shares. Treat every daemon, database, configuration file, and backup as security-sensitive. Protocol assumptions are documented in the [threat model](threat-model.md). Report vulnerabilities through the private process in [SECURITY.md](../SECURITY.md).

## Process isolation

Run each Holder, Ledger validator, and committee member as a separate operating-system identity. A committee operator should run one share per process and use independent hosts or failure domains where possible.

Thunderbolt configuration is secret-free. It contains public identities, policy, limits, and references to separately protected credentials. Runtime validation requires absolute paths, owner-only files and directories, exact manifest hashes, and fresh inode checks before handoff.

The local control plane uses an owner-only Unix socket. It is separate from Ledger, CometBFT, Bitcoin Core, and committee traffic. Do not expose the control socket through a network proxy.

## Keys and shares

- Generate Holder keys, committee shares, transport keys, and release keys with an operating-system CSPRNG.
- Keep Holder secrets and committee shares encrypted at rest.
- Store wrapping and transport keys in an OS keyring, HSM, hardware-backed keystore, or another protected credential provider.
- Never put private keys, shares, passwords, tokens, decrypted records, or signing nonces in TOML, command arguments, logs, tests, issue reports, or source control.
- Persist signing sessions before releasing a partial signature. Burn every nonce after success, failure, timeout, or restart.
- Bind signing authorization to the exact channel, step, transaction, fee policy, participant set, and aggregate nonce.

## Protocol transport

- Use mutual TLS for remote Ledger and committee connections.
- Pin validator, committee, and service identities to the deployment manifest.
- Sign protocol entries over canonical, domain-separated digests.
- Apply frame, item-count, aggregate-work, and deadline limits before expensive parsing or proof verification.
- Retry a mutation only with its original request identifier. Treat an uncertain broadcast as ambiguous until the exact request is found in finalized Ledger state.

## Ledger and finality

The Thunderbolt Ledger must provide one immutable order of entries and keep committed data available. Entry signatures authenticate the actor. They do not prove consensus finality.

The Ledger application executes deterministic blocks behind CometBFT. Clients verify the validator chain, application hash, executed entry, and Merkle proof before issuing a capability to Holder or committee code. Complete block scans include empty blocks so a consumer cannot skip finalized history.

Operators must keep the validator roster, consensus profile, Ledger limits, and RPC trust policy consistent across replicas. Source rotation must use the configured trust transition rather than replacing a peer key in place.

## Durable state and rollback protection

Participant records are encrypted and committed atomically. Holder and committee processes use an external rollback floor before treating a local secret-state transition as final. The floor must be independently administered and authenticated; a sibling file beside the participant database is not an independent anchor.

Use one durable database per process identity. Do not copy a live database into a second instance. A copied vault can create stale-state signing or nonce reuse even when the two processes do not run at the same time.

Backups must be encrypted and labeled with the deployment, network, process identity, schema, and last finalized state. Restore into an empty directory, verify the external checkpoint, replay finalized Ledger history, and enable mutations only after reconciliation succeeds.

## Bitcoin settlement

- Pin the Bitcoin network and genesis hash.
- Bind every channel to the complete funding outpoint.
- Enforce the configured confirmation policy before accepting funding or settlement as stable.
- Track replacements, evictions, and reorganizations.
- Rebuild and verify the exact closing transaction before signing begins.
- Keep wallet and signing credentials outside the Ledger process.

## Logs and monitoring

Logs may include public identifiers, heights, entry hashes, durations, and status codes. They must not include secrets, shares, tokens, decrypted values, credential paths, or nonce material.

Monitor Ledger lag, committee quorum, pending transfers, signing sessions, Bitcoin height and reorganizations, database latency, backup age, queue pressure, and repeated authorization failures.

## Release controls

- Build from a clean signed source tag with the pinned Rust toolchain and `Cargo.lock`.
- Run formatting, strict linting, unit tests, integration tests, and restart tests.
- Scan dependencies, licenses, source history, release archives, and container contents.
- Produce checksums and a software bill of materials for the exact binaries.
- Verify release archives in a clean environment before publication.

Mainnet activation requires the complete Open, Transfer, committee update, and Finalize path; reviewed distributed key generation and threshold signing; production rollback-floor and transport providers; multi-process restart and reorganization tests; and an independent security audit. Until those gates are complete, use regtest or signet.
