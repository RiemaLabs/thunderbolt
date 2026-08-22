# Release process

Bitcoin Thunderbolt uses release candidates before any stable release. `v1.0.0-rc.1` is a developer and regtest milestone. It is not a promise of mainnet safety.

## Version policy

- `v1.0.0-rc.N` may change control APIs and local storage with documented migrations.
- Protocol event or signature-format changes require an explicit protocol-version change, even during the RC series.
- `v1.0.0` requires every mainnet gate in [Security](security.md) and an external audit.
- Patch releases preserve protocol and storage compatibility unless a security response documents an emergency exception.

The daemon, CLI, event envelope, database, and release metadata report the same software and protocol versions.

## Branch policy

Release work is prepared on `release/1.0` from the reviewed `release/open_source` baseline. The publication branch is not pushed or made public until [Publication checklist](publication-checklist.md) passes.

Changes reach the release branch through reviewed pull requests. Cryptography, protocol state, serialization, storage migrations, signing, authorization, and Bitcoin settlement require focused owner review. The author does not provide the only approval for a security-critical change.

## RC gates

Every RC must pass:

1. Clean source build with the pinned toolchain on supported platforms.
2. Formatting, linting, unit, integration, documentation, and benchmark-regression checks.
3. Multi-process regtest tests for Open, Invoice, Transfer, committee update, and Finalize features included in the release.
4. Restart tests at every durable transition and signing boundary.
5. Duplicate, replay, stale sequence, wrong network, malformed proof, and resource-limit tests.
   Bitcoin backend changes also require the opt-in live gate described in [Testing](testing.md); an ignored harness is not treated as automatic CI evidence.
6. Database migration, backup, clean-host restore, and downgrade-policy checks.
7. Dependency vulnerability, license, secret, and provenance scans.
8. Review of unsafe code, production panics, test keys, fixed nonces, debug endpoints, and fail-open paths.
9. Operator documentation verified against the built binaries.
10. Signed checksums, software bill of materials, source commit, and known-limit release notes.

An RC may ship with an incomplete feature only when the binary disables it and the release notes say so plainly.

## Mainnet gates

Stable `v1.0.0` also requires:

- the full production architecture and trust model implemented and tested
- mainnet explicitly enabled through a reviewed change
- production Ledger guarantees independently validated
- one-share-per-process committee deployment and threshold signing audit
- Bitcoin fee, mempool, confirmation, replacement, and reorganization tests
- load, soak, failure-injection, and recovery results at documented limits
- independent security audit with critical and high findings resolved or publicly accounted for
- at least one public RC period with no unresolved release-blocking defect
- support, incident, disclosure, and maintainer coverage confirmed

The paper's acceptance and benchmark results are not release gates and do not replace them.

## Prepare a release

1. Freeze the intended commit and protocol version.
2. Update `CHANGELOG.md`, operator guides, API status, supported versions, and known limits.
3. Run the publication and release checks from a fresh clone.
4. Build source and binary artifacts in a clean environment.
5. Generate checksums, dependency inventory, licenses, and a software bill of materials.
6. Rebuild in a second environment and compare outputs where supported.
7. Have a maintainer who did not build the first artifacts verify them.
8. Create an annotated, signed tag.
9. Publish release notes with upgrade, backup, rollback, compatibility, and security information.
10. Verify the remote tag and every downloadable artifact after publication.

Do not sign a tag before the exact commit and generated artifacts have passed review.

## Release notes

Each release note includes:

- software and protocol version
- supported Bitcoin networks and explicit mainnet status
- implemented roles and workflows
- database and API compatibility
- security fixes and disclosure references
- operator actions before and after upgrade
- known limits and unavailable features
- artifact verification instructions
- contributors

Avoid language such as "production-ready" until the stable mainnet gates pass.

## Rollback

Every release needs a tested rollback decision before publication.

- If no migration or protocol event was committed, stop, restore the previous binary, and verify state.
- If a reversible migration ran, use only the tested rollback procedure shipped with the release.
- If the node committed a new protocol version or irreversible migration, do not start an old binary. Restore from a verified pre-upgrade backup in read-only mode and coordinate recovery.
- Preserve failed data directories and logs for analysis. Do not overwrite the only evidence with a restore.

The release manager records the exact rollback boundary in the notes.

## Post-release

After publication, verify the public source tag, checksums, signatures, software bill of materials, documentation links, container or package provenance, and vulnerability-reporting channel. Monitor installation and migration reports. Add confirmed defects to the changelog and security process rather than silently replacing artifacts.
