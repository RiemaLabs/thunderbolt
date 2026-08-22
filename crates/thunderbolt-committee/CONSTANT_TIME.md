# Secret-handling and constant-time review

Review date: 2026-08-21

Scope: `thunderbolt-committee` production code. The `insecure-regtest` dealer and
test-only in-memory vault are excluded from production conclusions.

## Result

The committee runtime adds no secret-dependent indexing, sorting, division,
remainder, logging, formatting, or early-exit byte comparison. Shamir addition
and subtraction, scalar parsing, point multiplication, and public commitment
comparison are delegated to the `secp`/libsecp256k1 path. The persistent Shamir
share is stored as a non-`Clone`, non-`Debug`, zeroizing 32-byte value. The
Paillier decryption key zeroizes on drop through `libpaillier`. Decrypted
Paillier plaintext and encoded vault records are wrapped in `Zeroizing` values.

The update acknowledgement contains only public identifiers and hashes. Its
digest commits to the new public Feldman commitment but never serializes the
old share, refresh share, or updated share. The signing adapter never receives
or stores secret nonce bytes; it persists public commitment hashes and burns a
session before asking the signer for a signature share.

## Reviewed secret flows

1. A production constructor consumes one `ProvisionedMemberPackage` and moves
   one Paillier decryption key and one `ShamirShare` into
   `CommitteeMemberState`. No production function accepts a committee secret or
   reconstructs one.
2. `apply_committed_refresh` verifies the recipient share proof, complete public
   distribution, and committed transfer, selects one member ciphertext by
   public member id, decrypts only that ciphertext, and compares its public
   point to the Feldman evaluation.
3. The new scalar is computed with secp256k1 scalar subtraction. It is encoded
   immediately into a new zeroizing `ShamirShare` and replaces the old share
   only after the encrypted vault compare-and-swap succeeds.
4. Vault serialization uses bounded buffers. Secret intermediate buffers are
   zeroizing, and the vault API explicitly labels the only plaintext borrow.
5. Error variants and public `Debug` implementations contain no secret-bearing
   fields. Secret state, packages, vault plaintext, and dealer output implement
   neither `Clone` nor `Debug`.

## Residual limitations

- `libpaillier`/`unknown_order` modular exponentiation is existing core
  cryptography and is not demonstrated constant-time by this review. Production
  operators must treat Paillier timing and shared-host leakage as an audit
  blocker until an audited constant-time backend or an equivalent isolation
  argument is adopted.
- `secp::Scalar` is a copyable dependency type. This crate keeps the persistent
  share in zeroizing bytes, but short-lived scalar copies created for arithmetic
  cannot be reliably scrubbed through the current dependency API.
- The zero-updated-share rejection necessarily reveals that a proposed refresh
  equals the current share. The protocol already rejects that state explicitly;
  only authenticated, ledger-committed transfers may reach this branch.
- Static source review cannot establish cache, speculative-execution, scheduler,
  or hardware side-channel resistance. Those require deployment-specific
  testing and an external cryptographic audit.

No unsafe code or panic/unwrap/expect paths are permitted by crate-level lints.
