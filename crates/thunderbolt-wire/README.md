# thunderbolt-wire

`thunderbolt-wire` is the public, versioned codec for Bitcoin Thunderbolt proof
messages. Version 1 carries invoice, transfer, encrypted-share, and threshold
refresh statements and proofs. A transfer envelope also carries the public
anchor transition that the verifier must check.

Every envelope binds its proof to:

- protocol version 1;
- the Bitcoin network;
- a deployment identifier;
- the committee epoch;
- a channel identifier;
- an invoice identifier; and
- an explicit transfer step, when applicable.

Identifiers and cryptographic values use lowercase hexadecimal. The decoder
rejects uppercase, odd-width, non-minimal integer, unknown-field, invalid-point,
invalid-key, oversized-field, and oversized-message encodings before invoking
the core verifier. `CanonicalDigest` hashes typed fields in a fixed binary order,
so whitespace and JSON object formatting cannot change a message digest.

This crate has no serializable witness or private-key types. In particular, it
cannot encode invoice refresh scalars, Paillier decryption keys, holder secrets,
proof nonces used as witnesses, decrypted committee shares, or updated committee
shares. Keep those values in the protocol and storage layers that own them.

Use `to_json_vec` and `from_json_slice` at trust boundaries, then call `verify`
on the decoded envelope before changing protocol state.
