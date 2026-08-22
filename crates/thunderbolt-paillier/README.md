# thunderbolt-paillier

This crate is the isolated Stage-A arithmetic backend for Thunderbolt protocol
version 2. It implements one parameter set only:

- two distinct 1536-bit prime factors;
- an exact 3072-bit Paillier modulus `N`;
- the fixed generator `g = N + 1`;
- 6144-bit arithmetic modulo `N^2`;
- 384-byte modulus and public proof-nonce encodings; and
- 768-byte ciphertext encodings.

There is no profile selector and no 2048-bit fallback. The crate is not a
default workspace member and is not integrated into core, wire, Holder,
committee, verifier, runtime, or RPC code.

## Arithmetic representation

Production values use RustCrypto `crypto-bigint` 0.7 fixed multiprecision
types: `U1536`, `U3072`, and `U6144`. The crate does not expose a generic big
integer. Public methods accept typed fixed-width values or bounded byte strings.
This keeps attacker-controlled precision out of arithmetic and makes every
secret-path loop bound a compile-time protocol constant.

`crypto-primes` supplies maintained FIPS 186-5 Miller-Rabin plus Lucas probable
prime generation and reload validation, configured for a false-accept target
below `2^-128`. Offline key generation uses a ChaCha20 CSPRNG seeded from
operating-system entropy. It rejects equal factors, factors with
`|p - q| <= 2^1436`, and pairs whose product does not have the exact 3072-bit
width evaluated in the paper. Probable-prime validation is not a primality
proof.

## Key-validity boundary

`RawPublicKey3072` checks only transport structure: exact width, top bit, and
oddness. It has no arithmetic methods and cannot be promoted by this crate.
`PublicKey3072` is created only from a locally generated or revalidated
`SecretKey3072`. Reload accepts only an authenticated record produced by the
reviewed generator; the fixed-width record is not itself an authenticity
mechanism.

This is deliberate. A later protocol integration must define an authenticated
committee registry or a reviewed proof that an externally supplied modulus
satisfies the key-validity conditions required by the VEDL argument. Exact
width and oddness alone are not that proof.

## Secret handling

Secret keys, plaintexts, encryption openings, nonces, and secret-key records
implement neither `Clone` nor `Debug`. They zeroize on drop. Plaintext input is
an exact 384-byte `SecretPlaintextBytes3072` consumed from `Zeroizing` ownership
and validated under one exact modulus. Secret records are consumed through
`SecretKeyBytes3072`; `from_borrowed_secret_bytes` is explicitly a compatibility
adapter that copies into zeroizing ownership and cannot erase the caller's
original buffer.

Production encryption accepts no caller RNG or nonce. It seeds a zeroizing
ChaCha20 CSPRNG from the operating system, binds the resulting non-cloneable
opening to the full 384-byte modulus, and never exposes or restores nonce bytes.
Proof-opening material consumes both the statement opening and a fresh
commitment opening after exact-key checks. Deterministic composition and nonce
inspection exist only under `cfg(test)` to demonstrate the former nonce-reuse
failure and lock test vectors.

The secret record is versioned and fixed-width:

```text
magic[8] || version_u16_be || p[192] || q[192]
```

Persist it only inside an authenticated encrypted keystore. Loading reruns FIPS
probable-prime checks and rechecks factor width, distinctness, minimum distance,
and the derived exact-width modulus before constructing a key.

## Status

Stage A is arithmetic evidence, not production activation. Core and wire still
use their existing fail-closed v2 boundary. Before integration, this crate
requires independent cryptographic review, cross-architecture constant-time
evidence, protocol key-validity design, and real proof transcript vectors.
The crate cannot itself guarantee that offline APIs run before a daemon starts
listening; that startup/process separation is a mandatory integration gate.

See [CONSTANT_TIME.md](CONSTANT_TIME.md), [LICENSE_BOUNDARY.md](LICENSE_BOUNDARY.md),
and [ASSEMBLY_REVIEW.md](ASSEMBLY_REVIEW.md).
