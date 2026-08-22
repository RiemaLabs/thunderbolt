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

## Stable version 2 binding

`ChannelBindingV2` corrects a version 1 scoping problem without changing any
version 1 hash or wire encoding. Its stable `context_id` binds the protocol
suite and version, Bitcoin network, deployment, complete 36-byte funding
outpoint, exact Bitcoin genesis hash, committee epoch and descriptor digest,
and anchor parameter-suite identity. `OperationBindingV2` adds the invoice
identifier and, for transfers, a positive step as separate proof-transcript
inputs. Changing an invoice or step therefore never changes the channel's
stable `context_id`.

Suite, committee-descriptor, anchor-suite, and genesis identifiers are non-zero
32-byte values. Their source descriptors and chain identity must be pinned and
authenticated by deployment configuration; this codec does not decide their
signature or governance policy.

The binding layer deliberately does not define actor signatures. The separate
`thunderbolt-ledger` crate now layers a reviewed `bip340_v1` signed proposal,
actor-derived participant identity, chain-scoped request digest, predecessor,
role, and canonical event bytes over `ChannelBindingV2`. Keeping these layers
separate prevents a generic signature blob from weakening the stable channel
binding or changing version 1 encodings.
