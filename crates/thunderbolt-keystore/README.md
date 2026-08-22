# Bitcoin Thunderbolt keystore

`thunderbolt-keystore` is the encrypted local vault used by a Thunderbolt
Holder or by one independently operated Threshold Committee member. It stores
only participant-local secret material. The Thunderbolt Ledger must never open
or copy this vault.

The on-disk format uses Argon2id to derive a key from an operator
password, followed by XChaCha20-Poly1305 authenticated encryption. The
authenticated context binds the format version, Bitcoin network, deployment
identifier, positive committee epoch, exact committee-descriptor digest,
participant role, node identity, KDF settings, salt, nonce, vault revision,
record and receipt counts, and ciphertext length. Passwords, derived keys,
decrypted payloads, and opaque record values are zeroized on drop.

The vault deliberately exposes a narrow API:

- `RecoveryVault::create` is no-clobber and creates an owner-only file without
  exposing secret records.
- `RecoveryVault::open` authenticates a file but remains restricted until
  `anchor` loads an exact checkpoint from a `RollbackFloorStore`.
- `Vault::open_anchored` combines recovery and exact external anchoring for
  normal production startup.
- namespaced keys separate wallet, Paillier, channel, invoice, credential,
  committee-share, signing-nonce, and adapter-owned state.
- `Vault::transact` checks the authenticated vault revision and every expected
  record version before atomically replacing multiple records, then advances
  the exact external checkpoint before returning.
- secret reads exist only inside the transaction callback. Owned callback output
  is withheld until checkpoint CAS succeeds and is dropped on failure. Even a
  read-only callback writes a receipt and advances the checkpoint, preventing a
  copied stale vault from releasing output.
- caller-chosen transaction identifiers are persisted with a canonical digest
  of the expected versions and mutations. Exact retries are idempotent;
  same-identifier, different-mutation retries fail closed.
- consumed signing nonces become durable tombstones and cannot be reinserted.
- records, keys, values, total plaintext, transaction width, and retained
  idempotency receipts all have explicit bounds.
- `Vault::backup_to` never overwrites a destination.
- backups preserve the exact authenticated encrypted bytes and checkpoint.
  `Vault::restore` requires that exact checkpoint from the independent store
  before creating an empty target.
- one advisory lock file prevents two cooperating processes from opening the
  same live vault at once.

Participant adapters serialize each independently recoverable secret object
into a `SecretValue`; they do not need to combine a channel or all engine state
into one fixed record. A transaction can update up to 256 records, one record
can hold up to 512 KiB, and a vault can hold up to 4,096 records with at most
8 MiB of decrypted value bytes. Applications may prune old transaction
receipts only after retaining an external durable request history. Nonce
tombstones are never pruned.

An authenticated numeric revision does not stop two copied vault paths from
diverging independently at the same next revision. `VaultCheckpoint` therefore
commits to both the revision and the exact randomized encrypted file. A copied
fork has a different state digest even at the same revision and loses the
external compare-and-swap.

`RollbackFloorStore` is the integration contract for that independent anchor.
It keys checkpoints by the complete authenticated `VaultIdentity` and provides
an atomic expected-checkpoint to exact-next-checkpoint transition. Initialization
anchors revision zero. Later transitions advance exactly one revision. An exact
next checkpoint is idempotent; stale expected checkpoints, skipped revisions,
and equal-revision different-digest forks conflict. Success is allowed only
after the checkpoint is durable. The backend error must not format secrets or
authentication credentials.

This crate intentionally does not implement the trait with a local file: a file
stored with the vault or covered by the same backup cannot detect rollback of
that trust domain. The restricted recovery handle exposes only identity and
checkpoint. It cannot read or mutate records until the independent store
confirms the exact checkpoint. Transaction callbacks must not perform external
side effects themselves; they return owned values for release by the caller
only after the library finishes the external checkpoint transition.

On Unix, vault, backup, temporary, and lock files are opened with
`O_NOFOLLOW | O_CLOEXEC`. The implementation rejects symlinks, non-regular
files, and files readable or writable by group or other users.

The library does not read passwords from command-line arguments or environment
variables. A daemon should obtain a password through an interactive prompt or
an operating-system credential facility, move it into `Password`, and avoid
retaining another copy.

If an atomic live-vault replacement returns an error, the open handle is poisoned.
This is intentionally conservative because an error after rename can leave the
new file visible while memory still reflects the old state. `AmbiguousWrite`
carries the exact attempted candidate checkpoint. The adapter drops the
poisoned handle, opens a restricted recovery handle, compares the actual file
against the prior and candidate checkpoints, and resolves the external CAS
before secrets can be exposed again.
