# Publication checklist

Do not make the repository public until every required item is checked by a named owner. A clean working tree is not enough. Git history, release artifacts, legal rights, private reporting, and remote settings are part of the publication surface.

## Source and branch

- [ ] `release/1.0` is based on the reviewed `release/open_source` baseline.
- [ ] The intended public commit is recorded and reviewed from a clean clone.
- [ ] No untracked local artifact is required to build, test, configure, or understand the release.
- [ ] Research code is clearly separated from operator runtime code and cannot enter a production binary by default.
- [ ] Mainnet remains disabled in the RC binary and tests confirm fail-closed behavior.
- [ ] The public remote, default branch, branch protection, tag protection, and visibility change have explicit owner approval.

## License and rights

- [ ] `LICENSE` is the unmodified Apache License 2.0 text.
- [ ] `NOTICE` names only rightsholders and notices that have been verified.
- [ ] Every contributor and employer ownership claim has been reviewed for the right to publish under Apache-2.0.
- [ ] Maintainers have decided whether a contributor license agreement or Developer Certificate of Origin is required, and contribution automation matches that decision.
- [ ] Dependency licenses and required notices have been generated and reviewed.
- [ ] Third-party code, test vectors, images, data, and benchmark artifacts have a recorded source and compatible redistribution terms.
- [ ] The accepted paper and ACM-formatted PDF are treated as separate copyrighted works. They are not placed under the repository license without confirmed rights.
- [ ] Product names, logos, and trademarks have been reviewed. Apache-2.0 does not grant trademark rights.

The workspace already declares Apache-2.0. The license text must not be weakened with an extra source-code restriction. Resolve any ownership uncertainty before publication instead.

## Historical secrets

- [ ] The two known historical secret locations in [History sanitization](history-sanitization.md) have been removed from every public ref.
- [ ] The exposed Bitcoin seed or key material has been retired. If it ever controlled funds, funds were moved to newly generated keys before the history rewrite.
- [ ] All API, RPC, CI, deploy, package, cloud, and signing credentials found in any ref, tag, issue export, or artifact have been rotated or revoked.
- [ ] A full-history secret scan passes with secrets redacted in scanner output.
- [ ] Scanner findings are reviewed by a human. An allowlist contains only documented false positives and test vectors that cannot authorize any real system.

Deleting a file in the tip does not remove its contents from Git history or existing clones.

## Repository size and generated history

- [ ] Historical `benchmarks/sp1-transfer-benchmark/script/target/**` content has been removed from every public ref.
- [ ] No other build directory, object file, archive, database, wallet, log, or crash dump remains in history.
- [ ] The largest remaining blobs are intentional source or benchmark artifacts with documented licenses.
- [ ] A fresh clone has an acceptable transfer and checkout size.
- [ ] Ignore rules prevent generated target directories from returning.

The current history contains generated SP1 build blobs up to 61,041,024 bytes and produces a pack of about 504 MiB. This is a publication blocker even though the current tree ignores nested target directories.

## Security and operations

- [ ] GitHub private vulnerability reporting is enabled and tested.
- [ ] `SECURITY.md` names a monitored private contact or working private reporting route.
- [ ] Maintainers and backups for security response, release management, and CODEOWNERS teams are assigned.
- [ ] Threat model, security limits, operator guide, configuration, backup, restore, and incident procedures match the current binaries.
- [ ] No default listener exposes an unauthenticated administrative API.
- [ ] Example configuration contains no real endpoint, account, secret, address, or operator identity.
- [ ] Logs, panic messages, and metrics have been checked for secret leakage.
- [ ] External security audit scope and unresolved findings are recorded honestly.

## Code and release quality

- [ ] Formatting, linting, unit, integration, documentation, and regression checks pass from a clean clone.
- [ ] Multi-process tests cover each workflow claimed by the release notes.
- [ ] Crash recovery, idempotency, replay, duplicate, ordering, quorum-loss, and Bitcoin-reorganization tests pass.
- [ ] Database migrations, encrypted backup, backup verification, and clean-host restore pass.
- [ ] Dependency vulnerability, license, provenance, and secret scans pass.
- [ ] Release binaries contain no fixed keys, fixed signing nonces, mock committee shortcuts, unfinished signing paths, debug bypasses, or production panics.
- [ ] Checksums, signed artifacts, software bill of materials, source commit, and reproducible build instructions are ready.

## Community files

- [ ] README status, quickstart, roles, limitations, and documentation links are accurate.
- [ ] `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `GOVERNANCE.md`, `SUPPORT.md`, issue templates, pull request template, and CODEOWNERS are active and point to real maintainers.
- [ ] GitHub Discussions, issue labels, project boards, and support routes mentioned in documentation are enabled.
- [ ] Security issues are routed away from public issue templates.
- [ ] The first changelog and release notes call the software an RC and say that mainnet is not approved.

## Clean-clone rehearsal

Perform the final rehearsal in a new location with no local caches or credentials:

1. Clone the candidate public remote.
2. Verify refs, tag signatures, and the intended source commit.
3. Run history secret and large-blob scans.
4. Build and test with the pinned toolchain.
5. Follow every quickstart command exactly as written.
6. Verify that mainnet startup fails.
7. Inspect generated packages, containers, archives, logs, and software bill of materials.
8. Open each documentation and community link.
9. Submit a private test security report and confirm receipt.
10. Record sign-off from release, security, legal, and operations owners.

Only after this rehearsal passes should an owner change repository visibility or push rewritten public refs.
