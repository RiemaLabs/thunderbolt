# Contributing

Bitcoin Thunderbolt welcomes code, documentation, tests, review, and protocol analysis. This software can control Bitcoin, so small changes may need more review than their line count suggests.

Read [Architecture](docs/architecture.md), [Threat model](docs/threat-model.md), and [Governance](GOVERNANCE.md) before changing protocol state, cryptography, persistence, signing, or operator behavior.

## Start with the right channel

- Use a public issue for a reproducible bug, scoped feature request, or documentation problem.
- Use a discussion issue before a breaking protocol, wire, storage, trust-model, or role change.
- Follow [SECURITY.md](SECURITY.md) for anything that could expose funds, keys, shares, credentials, privacy, or release integrity.

Do not put a suspected vulnerability in a public issue.

## Development setup

Install the Rust toolchain pinned by `rust-toolchain`, then run:

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Some paper comparison benchmarks require Docker, separate toolchains, or long runs. Their prerequisites and expected outputs live under `research/benchmarks/` and `research/artifacts/`. A normal protocol change should not require every research benchmark, but it must run the relevant regression test.

## Make a focused change

- Keep a pull request limited to one coherent problem.
- Add tests that cover invalid and interrupted paths as well as the successful path.
- Avoid unrelated formatting, dependency, or generated-file changes.
- Preserve backward compatibility unless the proposal includes versioning, migration, and activation plans.
- Update operator and API documentation in the same pull request as behavior changes.
- Never add a real key, seed, share, endpoint credential, wallet, database, log, or build directory.

Generated research outputs belong only in their documented artifact location. Rust `target/` directories never belong in Git.

## Sensitive changes

Changes in these areas require focused reviewer expertise:

- proof statements, transcript domains, cryptographic assumptions, and randomness
- canonical encoding, event hashing, and signature context
- channel transitions, idempotency, ordering, and replay defense
- committee resharing and threshold signing
- secret storage, migration, backup, restore, and crash recovery
- authentication, authorization, remote listeners, and rate limits
- Bitcoin transaction building, fee policy, confirmations, and reorganizations

A sensitive pull request should state the invariant it preserves, its failure behavior, new tests, and any residual risk. Include test vectors for serialization or cryptographic changes.

## Pull request checklist

Before requesting review:

1. Rebase on the current target branch without rewriting other contributors' work.
2. Run formatting, linting, workspace tests, and the relevant integration tests.
3. Review the diff for secrets, debug output, panics, fixed nonces, and generated files.
4. Update `CHANGELOG.md` for an operator-visible change.
5. Update the threat model, API contract, configuration, or runbook if the change affects them.
6. Explain how to reproduce the result from a clean checkout.

Maintainers may ask for a smaller pull request, an issue design record, more failure tests, or independent cryptographic review before merge.

## Commit and review practice

Write imperative commit subjects that say what changed. Signed commits are encouraged for contributors and required for release tags. Do not squash away meaningful authorship or third-party attribution.

Authors do not approve their own security-critical changes. Maintainers use protected branches and required reviews according to [GOVERNANCE.md](GOVERNANCE.md).

## License

The repository is licensed under Apache-2.0. Unless you explicitly state otherwise, an intentional contribution submitted for inclusion is provided under the terms in Section 5 of the Apache License 2.0.

Only submit work that you have the right to license. If your employer or another party may own the work, obtain authorization before submitting. Preserve third-party copyright, patent, attribution, and license notices.

## Conduct

Participation in issues, reviews, discussions, and project spaces follows the [Code of Conduct](CODE_OF_CONDUCT.md).
