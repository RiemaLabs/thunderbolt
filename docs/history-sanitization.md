# History sanitization

The current tip no longer contains the old client files or nested SP1 build output, but Git objects remain in repository history. They must be removed before public release. This document names the known blockers without reproducing any secret value.

History rewriting is destructive coordination work. Perform it in a new mirror clone, preserve a restricted backup, rotate exposed credentials first, and obtain explicit approval for the exact refs and remote before any force push.

## Known secret-bearing history

A full-history scan found two secret-bearing source locations:

| Commit | Historical path | Secret identifier | Required response |
| --- | --- | --- | --- |
| `a7fc03ae1516838450b4a2b292945cd1d63621c8` | `crates/thunderbolt-clients/src/bip322.rs` | `deployer_secret_seed` | Remove the file from public history. The test also printed derived private-key bytes, so retire the full identity and treat logs from that test as sensitive. |
| `1a0d9475e132da8622b3580fa74618390066e90f` | `crates/thunderbolt-clients/tests/client.rs` | `zooey_secret_key` | Remove the file from public history and retire the corresponding key. Review the adjacent historical client endpoints for any separate credentials. |

Do not copy the values into tickets, pull requests, replacement maps, shell commands, or scan reports. If either value ever controlled a mainnet or testnet identity with assets or privileges, move those assets to newly generated keys and permanently stop using the exposed identity. Deleting or rewriting Git history cannot make an exposed Bitcoin private key safe again.

The scan that identified these locations used Gitleaks with full redaction. Run independent scanners and manual review before publication because one tool cannot prove that history is clean.

## Known oversized history

Historical generated files under:

```text
benchmarks/sp1-transfer-benchmark/script/target/**
```

include compiled binaries and Rust dependency archives. The largest observed blob is 61,041,024 bytes at:

```text
benchmarks/sp1-transfer-benchmark/script/target/release/deps/transfer_compare-bb8de42377a07351
```

The current clone reports a Git pack of about 504 MiB. Commit `114b6b2` added ignore rules for nested benchmark target directories, which prevents new tracked output but does not remove existing objects.

Do not move this generated tree to Git LFS. It is rebuildable output and does not belong in public history.

## Rewrite procedure

The following is a runbook, not authorization to rewrite a remote. Replace the source and destination placeholders with reviewed URLs. Never put a credential in either URL or a command argument.

1. Rotate or retire the known secret material.
2. Freeze writes to every affected branch and tag.
3. Record the old ref tips in a restricted incident record.
4. Create a mirror clone in a new temporary directory.
5. Remove the two historical files and generated target tree from all refs.

Example using `git-filter-repo`:

```bash
git clone --mirror <private-source-url> thunderbolt-lib-sanitized.git
cd thunderbolt-lib-sanitized.git

git filter-repo --force \
  --path crates/thunderbolt-clients/src/bip322.rs \
  --path crates/thunderbolt-clients/tests/client.rs \
  --path-glob 'benchmarks/sp1-transfer-benchmark/script/target/**' \
  --invert-paths
```

Removing the full historical test files is intentional. They are absent from the release tip, and keeping selected revisions creates unnecessary risk of retaining the sensitive literals.

After filtering, expire local references to removed objects and repack the sanitized mirror:

```bash
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

Do not run these cleanup commands in the only restricted backup of the original history.

## Verification

Verify the sanitized mirror before adding a destination remote:

```bash
git fsck --full

gitleaks git --redact=100 --exit-code 1 .

git rev-list --objects --all \
  | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' \
  | awk '$1 == "blob" {print $3, $2, substr($0, index($0,$4))}' \
  | sort -nr \
  | head -n 40

git count-objects -vH
```

Then perform manual checks:

- Search every ref for the two historical paths and identifiers.
- Search for seed, private-key, API-key, credential, token, password, wallet, keystore, and environment-file patterns.
- Inspect large remaining blobs and archives rather than assuming their extensions are safe.
- Confirm that expected source branches and tags still point to complete, buildable trees.
- Clone the sanitized mirror as a normal working repository and run the full release checks.
- Compare the release tip content with the approved pre-rewrite manifest.

Scanner output and review notes must contain paths, rule identifiers, and commit identifiers only. Keep actual secret matches fully redacted.

## Publish rewritten refs

Once the sanitized clone, build, tests, legal review, and [Publication checklist](publication-checklist.md) pass:

1. Create or select the approved empty public remote.
2. Add it as a new remote to the sanitized mirror.
3. Push only the approved branch and tag manifest.
4. Verify each remote ref and release artifact after the push.
5. Tell every collaborator that old commit identifiers and clones are obsolete.
6. Remove or archive old remote refs according to the incident plan.
7. Run the full-history secret scan against the public remote again.

Anyone with an old clone may still possess the removed objects. Rotation and identity retirement are therefore mandatory even after a successful rewrite.
