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

For version 1, use `to_json_vec` and `from_json_slice` at trust boundaries,
then call `verify` on the decoded envelope before changing protocol state.

## Protocol v2 raw envelopes

`PublicMessageV2` is a separate, closed message family for `Invoice`,
`Transfer`, `RecipientShare`, and `ThresholdRefresh`. Every envelope carries an
`OperationBindingV2` and the mandatory `protocol_v2_production_3072` Paillier
profile. Version 2 uses exact-width, left-padded byte values rendered as
lowercase hex: 384 bytes for a modulus or nonce, 768 bytes for a ciphertext,
and 81 bytes for a proof response. The JSON decoder requires the exact compact
canonical encoding emitted by `to_json_vec`.

Network code must call `decode_public_message_v2`. V2 semantic envelopes, raw
value wrappers, and nested statement/proof types deliberately do not implement
`Deserialize`, so a web or RPC framework cannot bypass the 2 MiB
whole-document cap or canonical encoding check by deserializing directly into a
public type. Private bounded DTOs exist only inside that decoder. The generic
`from_json_slice` function remains the unchanged version 1 compatibility API.

Each Fiat-Shamir `ProofContext` is derived from the stable channel context under
a v2-only domain. It additionally commits the mandatory production profile and
the complete operation. Invoice contexts include the expected transfer step;
Recipient and VESS contexts include the package id, expected step, and ordered
roster commitment. `ChannelBindingV2::context_id` itself remains unchanged.

Threshold messages additionally carry one deterministic package-intent ID over
the complete channel and invoice operation, expected transfer step, threshold,
and ordered member-id-to-key roster. The Recipient-share and refresh envelopes
must carry the same package binding, anchor base, and public delta. This binds
the implemented `tb/share` proof and VESS distribution as a reviewed two-message
package; it does not claim that `tb/share` is the paper's exact `R_inv^thr`
transcript.

The current fixed-width `libpaillier` backend cannot represent a 3072-bit
modulus squared or a 768-byte ciphertext. Version 2 decoding and canonical
digesting are available, but `to_core`, `from_core`, and `verify` intentionally
fail at the core raw-profile ingress before constructing a 3072-bit key. There
is no fallback to the legacy 2048-bit profile.

The 256-member topology fits the coordinated release caps. With maximum
identifiers and threshold 256, measured compact sizes are 212,661 bytes for the
wrapped `RecipientShare`, 1,491,757 bytes for
the wrapped `ThresholdRefresh`, 1,705,843 bytes for the corresponding canonical
`InvoiceEventV2`, 3,413,182 bytes for its hex-wrapped signed-proposal JSON, and
3,413,339 bytes for the Ledger-RPC request. The Ledger stack permits 2 MiB
`ArtifactV2` values while retaining v1's 1 MiB `Artifact`; events use up to
2 MiB minus a 2 KiB transport reserve, with 4 MiB signed
and RPC request bodies. Independent 8 MiB pending-Invoice and 11 MiB retained
state budgets keep snapshots and query responses bounded. The wire crate does
not shrink the protocol's 256-member topology to fit a transport limit.

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
