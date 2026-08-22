# Bitcoin Thunderbolt keystore

`thunderbolt-keystore` is the encrypted local vault used by a Thunderbolt
Holder or by one independently operated Threshold Committee member. It stores
only participant-local secret material. The Thunderbolt Ledger must never open
or copy this vault.

The on-disk format is versioned and uses Argon2id to derive a key from an
operator password, followed by XChaCha20-Poly1305 authenticated encryption. The
authenticated context binds the format version, Bitcoin network, participant
role, node identity, KDF settings, salt, nonce, and the exact set of record
types. Passwords, derived keys, decrypted payloads, and typed record buffers are
zeroized on drop.

The vault deliberately exposes a narrow API:

- `Vault::create` is no-clobber and creates an owner-only file.
- `Vault::open` authenticates the complete vault before returning any record.
- typed setters atomically replace the vault and sync both the file and parent
  directory before returning.
- `Vault::backup_to` never overwrites a destination.
- `Vault::restore` authenticates a backup before creating an empty target.
- one advisory lock file prevents two cooperating processes from opening the
  same live vault at once.

On Unix, vault, backup, temporary, and lock files are opened with
`O_NOFOLLOW | O_CLOEXEC`. The implementation rejects symlinks, non-regular
files, and files readable or writable by group or other users.

The library does not read passwords from command-line arguments or environment
variables. A daemon should obtain a password through an interactive prompt or
an operating-system credential facility, move it into `Password`, and avoid
retaining another copy.
