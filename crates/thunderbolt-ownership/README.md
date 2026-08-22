# Bitcoin Thunderbolt Holder Ownership Proof

This crate implements exactly the paper relation

`R_own = { (X; x) : X = xH }`.

The prover demonstrates knowledge of the current Holder scalar `x` for the
public anchor `X`, using the configured anchor base `H`. This is the ownership
proof used by the Finalize flow in Sections 4.2 and 5.1 of the protocol paper.

`FinalizeSigningContext` is derived from a validated `ChannelSnapshotV2`, an
immutable operator-owned anchor-suite registry, the
signature-authenticated Holder key, and the exact closing transaction. It
commits the Ledger chain and stable channel context, exact snapshot-state hash,
step (including zero), fixed lock key `P`, registered anchor suite and base,
current anchor, Holder participant/key, and closing transaction bytes plus
digest. These fields do not add a second proof equation or change `R_own`.

An `OwnershipEnvelopeV2` is untrusted. Its embedded statement is only an echo,
and carries the closing-transaction digest rather than duplicating the exact
transaction already present in `FinalizeEventV2`. `verify_ownership` requires a
separately derived `FinalizeSigningContext`, recomputes the digest from its
exact closing bytes, compares every public field, and computes the challenge
from those independently trusted bytes before checking the Schnorr equation.
There is no envelope-only equation-verification API.

The verification output proves only accepted knowledge for `X = xH`. It does
not prove that the closing transaction is valid, that the Committee approved
it, that a threshold was met, or that a signature exists. An
`ExternalVerifierV2::verify_finalize` adapter must check those separately.
The transcript-bound Holder key is the key supplied by that adapter after
Ledger actor-signature authentication; the ownership proof does not itself
prove possession of the BIP340 actor key.

The production prover samples its nonce directly from operating-system
randomness. Secret witness and random-byte buffers zeroize on drop. The binary
codec is versioned, canonical, bounded, and covered by a stable golden vector
and property tests. The accepted closing-transaction bound reserves 16 KiB
within the Ledger event cap for Finalize framing, this fixed-size ownership
envelope, and Committee attestation.
