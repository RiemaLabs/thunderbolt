# Bitcoin Thunderbolt keystore

`thunderbolt-keystore` is the encrypted local vault used by a Thunderbolt
Holder or by one independently operated Threshold Committee member. It stores
only participant-local secret material. The Thunderbolt Ledger must never open
or copy this vault.

The version-2 on-disk format uses Argon2id to derive a key from an operator
password, followed by XChaCha20-Poly1305 authenticated encryption. The
authenticated context binds the format version, Bitcoin network, deployment
identifier, positive committee epoch, exact committee-descriptor digest,
participant role, node identity, KDF settings, salt, nonce, vault revision,
record and receipt counts, and ciphertext length. Passwords, derived keys,
decrypted payloads, and opaque record values are zeroized on drop.

The vault deliberately exposes a narrow API:

- `Vault::create` is no-clobber and creates an owner-only file.
- `Vault::open` authenticates the complete vault before returning any record.
- namespaced keys separate wallet, Paillier, channel, invoice, credential,
  committee-share, signing-nonce, and adapter-owned state.
- `Vault::transact` checks the authenticated vault revision and every expected
  record version before atomically replacing multiple records.
- caller-chosen transaction identifiers are persisted with a canonical digest
  of the expected versions and mutations. Exact retries are idempotent;
  same-identifier, different-mutation retries fail closed.
- consumed signing nonces become durable tombstones and cannot be reinserted.
- records, keys, values, total plaintext, transaction width, and retained
  idempotency receipts all have explicit bounds.
- `Vault::backup_to` never overwrites a destination.
- `Vault::restore` authenticates a Holder backup and enforces an external
  minimum revision before creating an empty target. Committee signing-state
  restore is deliberately unsupported.
- one advisory lock file prevents two cooperating processes from opening the
  same live vault at once.

Participant adapters serialize each independently recoverable secret object
into a `SecretValue`; they do not need to combine a channel or all engine state
into one fixed record. A transaction can update up to 256 records, one record
can hold up to 512 KiB, and a vault can hold up to 4,096 records with at most
8 MiB of decrypted value bytes. Applications may prune old transaction
receipts only after retaining an external durable request history. Nonce
tombstones are never pruned.

An authenticated revision does not by itself stop replacement of a stopped
vault with an older, valid file. Plain `Vault::open` therefore refuses
committee-member vaults. Committee operators must call
`Vault::open_with_minimum_revision` with a positive revision from an
independently authenticated monotonic store, and must advance that external
floor after every nonce, share, or signing-state commit. A file below that
floor is rejected before any secret is exposed.

Holder restore also requires an externally trusted minimum revision. Plain
Holder open remains available for current channel state, whose public ledger
sequence rejects stale updates; any future Holder signing-session nonce store
must use checkpointed open and the same advance-before-release discipline as a
committee member.

On Unix, vault, backup, temporary, and lock files are opened with
`O_NOFOLLOW | O_CLOEXEC`. The implementation rejects symlinks, non-regular
files, and files readable or writable by group or other users.

The library does not read passwords from command-line arguments or environment
variables. A daemon should obtain a password through an interactive prompt or
an operating-system credential facility, move it into `Password`, and avoid
retaining another copy.

If any live-vault replacement returns an error, the open handle is poisoned.
This is intentionally conservative because an error after rename can leave the
new file visible while memory still reflects the old state. A poisoned handle
exposes no records and creates no backup; the process must drop it and reopen
from disk.
