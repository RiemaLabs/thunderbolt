# Paillier profiles and the 3072-bit backend gate

`thunderbolt-core` recognizes two closed parameter profiles:

- `LegacyRc2048V1` (`1`): 256-byte modulus and nonce, 512-byte ciphertext.
  Existing non-profile APIs and proof transcripts remain unchanged.
- `ProtocolV2Production3072` (`2`): 384-byte modulus and nonce, 768-byte
  ciphertext on the wire.

As with the legacy profile, modulus validation currently accepts the full
canonical byte width: a 384-byte modulus may have bit length 3071 or 3072. The
backend/profile migration must confirm this convention against the final paper
and wire specification before enabling v2; requiring the top bit would instead
need exact-3072 keygen rejection and resampling.

Callers cannot supply an arbitrary bit count. A statement or proof accepted
under one profile is not silently accepted under the other.

Paillier group elements are integers whose minimal encoding may be shorter than
the profile width. Sampling is uniform over the full valid group; it is never
rejection-sampled by minimal byte length. `encode_*_with_profile` left-pads valid
integers to the exact transport width, while `decode_*_with_profile` checks that
width before constructing or validating the number. Numerical validators accept
short minimal encodings after decoding and enforce only the profile, range, and
group invariants.

## Current production blocker

The compiled libpaillier 0.6 `crypto` backend represents numbers with a fixed
`crypto_bigint::U4096`. A 3072-bit modulus fits, but Paillier key construction
immediately computes the roughly 6144-bit value `N^2` and panics. All 3072-bit
raw-byte entry points therefore reject the profile before constructing
caller-controlled keys, ciphertexts, or nonces. Typed `_with_profile` APIs also
gate first, but callers must not construct a 3072-bit libpaillier
`EncryptionKey` on this backend: its constructor computes `N^2` before the
typed API can run. No synthetic 3072-bit round trip is reported as successful.

Changing only this crate to another libpaillier backend is not safe:

- Cargo feature unification would also retain the default `crypto` backend in
  other workspace crates and libpaillier rejects multiple number backends.
- `unknown_order`'s Rust and OpenSSL backends use variable-time modular
  exponentiation in their current upstream implementations.
- The GMP backend uses secure modular exponentiation, but introduces the
  LGPL-licensed `rug`/GMP stack and needs coordinated packaging, relinking, and
  legal review, plus a full side-channel audit of key generation, GCD, inversion,
  serialization, and decryption.

A real 3072-bit round trip remains a release blocker until the workspace adopts
a reviewed permissive arbitrary-precision backend, or completes the coordinated
GMP compliance and audit work. The profile and fail-closed API are versioned now
so that later backend work cannot silently alter v1 behavior.

## End-to-end integration blocker

The unqualified `PaillierAccountLocal::new`, proof, threshold, Holder, verifier,
and v1 wire APIs remain legacy 2048-bit compatibility paths. This scoped core
change does not make protocol v2 select the 3072-bit profile. A later coordinated
protocol/wire/Holder/committee/verifier migration must bind the profile in the
suite and route every production operation through mandatory profile-aware
ingress. Until then, v2 Paillier remains disabled rather than silently falling
back to 2048 bits.
