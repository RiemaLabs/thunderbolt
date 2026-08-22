# Secret-flow and constant-time review

Review date: 2026-08-22

Scope: `thunderbolt-ownership` production code. Test-only deterministic nonce
injection is excluded from production builds.

## Paper boundary

The only witness equation is `X = xH`. The fixed key, Ledger/channel context,
exact snapshot-state hash, step, Holder identity/key, anchor suite, and closing
transaction are public Fiat-Shamir inputs providing stronger domain
separation. Verification returns no transaction-validity,
committee-authorization, or signing capability.

The capability-minting verifier never trusts the context carried by the wire
envelope. It requires exact equality with a context independently derived from
a validated `ChannelSnapshotV2`, an immutable operator-owned `(suite_id, H)`
registry, the signature-authenticated Holder key, and exact closing bytes. An
envelope carries only the domain-separated digest of those closing bytes, and
there is no envelope-only equation-verification API. The verifier recomputes
the digest and Fiat-Shamir challenge from the independent exact bytes. This
prevents both closing-transaction substitution and a prover substituting
`H = X`, using witness `1`, and labeling the result with a real suite
identifier. Snapshot state hashing also prevents reuse across different
committed heads whose selected public fields happen to match.

## Secret flow

1. `OwnershipWitness` owns one canonical nonzero scalar encoding in a
   `Zeroizing<[u8; 32]>` and implements neither `Clone` nor `Debug`.
2. The production prover obtains 32 bytes directly from `getrandom`, keeps them
   in a zeroizing buffer, and rejection-samples only until they encode a
   nonzero secp256k1 scalar.
3. Witness matching, nonce commitment, and response arithmetic use the `secp`
   libsecp256k1 backend. No secret is formatted, serialized into the context,
   used as an array index, divided, reduced with Rust `/` or `%`, or included in
   an error.
4. The proof contains only the public nonce commitment and Schnorr response.
   The verifier processes public data only.

The suite registry, authenticated Ledger snapshot, and actor-authenticated
Holder key are trust inputs. This crate checks their internal and mutual
bindings but cannot authenticate their source. In particular, the ownership
equation does not prove BIP340 Holder-key possession.

## Timing review

Source review found no division, remainder, floating-point operation,
secret-dependent lookup, or secret byte comparison in the crate. Scalar
addition/multiplication and point multiplication are delegated to
libsecp256k1's secret-scalar operations. The random-scalar rejection branch
depends on fresh random bytes, not the witness. The witness-validity and
witness-mismatch branches reveal only whether a caller supplied a valid witness
for the already public statement, which is also the operation's explicit
success result.

`secp::Scalar` is a copyable dependency type, so short-lived scalar stack copies
cannot be reliably scrubbed through its current API. Persistent witness and RNG
buffers are zeroized, but compiler, cache, speculative-execution, hardware, and
OS side channels remain outside this source-level review. Production use still
requires the repository's external cryptographic audit gate.
