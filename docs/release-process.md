# Release process

Bitcoin Thunderbolt uses semantic versions and publishes stable releases from exact Git tags. Release work is prepared on a release branch and fast-forwarded to `release/open_source`.

## Version policy

- Pre-release versions may change local control and storage interfaces with documented migrations.
- A change to canonical protocol bytes, signatures, or state transitions requires explicit compatibility review.
- Patch releases preserve protocol and storage compatibility unless a coordinated security response documents an exception.

The daemon, CLI, release archive, and container must report the same software version and source commit.

## Required checks

Every release must pass:

1. A clean locked build with the pinned Rust toolchain.
2. Formatting, strict Clippy, unit, property, integration, and documentation tests.
3. Packaged multi-process regtest for every advertised protocol operation.
4. Restart tests at each durable state and signing boundary.
5. Replay, duplicate, stale-state, wrong-network, malformed-input, and resource-limit tests.
6. Database migration, backup, clean-host restore, and downgrade-policy checks.
7. Dependency advisory, license, secret, and provenance scans.
8. Operator documentation checked against the built binaries.
9. Checksums and a software bill of materials for the exact release archive.
10. Independent verification of the source commit and archive contents.

## Build a release locally

```bash
git status --short
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked --lib --bins --tests
scripts/generate-sbom.sh NEW_SBOM_DIRECTORY
scripts/package-release.sh v1.0.0 NEW_RELEASE_DIRECTORY
scripts/verify-release.sh --checksums-only NEW_RELEASE_DIRECTORY
```

Run the external CometBFT and Bitcoin Core interoperability gates with their pinned signed releases. Then install the archive on a clean host and run the documented operator topology.

## Release notes

Release notes include:

- source commit and tag
- supported networks and platforms
- protocol, storage, and configuration compatibility
- operator migration and rollback steps
- checksums, signature, and software bill of materials
- fixed security issues after coordinated disclosure
- known operational limits that affect deployment

## Publication

Fast-forward the reviewed release commit to `release/open_source`, then push an exact `vMAJOR.MINOR.PATCH` tag. The tag triggers `.github/workflows/release.yml`, which builds the platform archives, assembles a combined checksum manifest, extracts the matching changelog section, and publishes the GitHub Release. Do not rewrite a published release branch or replace assets under an existing version.

## Mainnet activation

Mainnet activation additionally requires the complete lifecycle integration, production threshold signing and key provisioning, operational recovery drills, external interoperability testing, and an independent security audit.

## Rollback

Keep the previous signed release available. A rollback must follow its storage compatibility policy. Never start an older binary against a newer database unless the release notes explicitly support that path.
