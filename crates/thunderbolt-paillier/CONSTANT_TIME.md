# Constant-time and key-generation boundary

## Scope

The constant-time target covers online operations on valid, key-bound semantic
types after a certified public key and local secret key exist:

- operating-system-randomized encryption and its fixed-width composition;
- decryption;
- homomorphic addition, subtraction, and public exponentiation;
- consuming proof-opening combination; and
- the Paillier response equation.

The target is fixed-width 64-bit x86_64 and AArch64 CPUs. RustCrypto documents
that `crypto-bigint` is not suitable for processors whose multiplication is
value-dependent. No constant-time claim is made for other architectures.

## Secret-path rules

- All integers have compile-time widths (`U1536`, `U3072`, `U6144`).
- Modular multiplication, exponentiation, inversion, GCD, and exact division use
  the non-`_vartime` RustCrypto APIs.
- Exponentiation always receives a public fixed bit count: 3072 bits.
- Secret-derived intermediate values are wrapped in `Zeroizing` where the API
  permits. Secret owning types implement `ZeroizeOnDrop` and are neither
  `Clone` nor `Debug`.
- Secret byte encoders fill a `Zeroizing` destination directly, one fixed-size
  machine word at a time; they do not first return an ordinary encoded array.
- Errors and public `Debug` output contain only static text or short public
  fingerprints.

Plaintext ingress consumes an exact-width zeroizing record, performs a
constant-time comparison with public `N`, and declassifies only the final
valid/invalid bit before constructing a key-bound semantic plaintext. The
online encoder returns exactly 384 bytes and has no secret-dependent truncation
path. Constant-time claims apply after these validity and exact-key invariants
hold. Faulted or manually zeroized values may return a static invariant error;
they are outside the valid-input claim.

### Narrow rejection-sampling exception

The private encryption sampler uses `random_mod_vartime`. This is intentionally
not a secret-dependent arithmetic shortcut. It performs rejection sampling
below the public modulus `N` on fresh CSPRNG output. RustCrypto documents that
the loop is variable-time in the public modulus and guarantees that it leaks
nothing about the accepted output except that it is below `N`. A constant-time
inversion then rejects zero and non-units, yielding the uniform conditional
distribution over `Z_N*` without conditioning on minimal byte width. Production
callers cannot supply, export, restore, or reuse this nonce.

Tests check fixed width, unit membership, uniqueness in deterministic samples,
leading-zero acceptance, and a locked low-nibble chi-squared regression. These
tests do not prove uniformity; the argument relies on rejection sampling from a
CSPRNG.

## Explicitly variable-time offline work

Prime search, FIPS probable-prime validation, and factor-distance checks are
variable-time and may reveal provisioning data. They are exposed only through
`OfflineKeyGenerator` and authenticated secret-record loading. The crate cannot
enforce process lifecycle: integration must call them before listening, or in a
separate provisioning process, never as a remote request handler or shared-host
oracle.

The prime library and fixed integer types are `Copy` internally, so compiler or
dependency temporaries may exist beyond the explicit zeroizing owners. This is
a residual limitation requiring assembly review, dynamic analysis, and an
external audit. Zeroization is best-effort memory hygiene, not a defense against
an already compromised process.

## Verification program

Before integration:

1. Inspect optimized assembly on x86_64 and AArch64 at O0 and O3/release.
2. Run dudect fixed-vs-random plaintext encryption and ciphertext decryption
   classes for at least 10 minutes per target.
3. Use Timecop or an equivalent dynamic taint tool to investigate any signal.
4. Re-run after compiler, `crypto-bigint`, `crypto-primes`, or target changes.
5. Obtain an independent review of Paillier composition, exact division,
   secret serialization, and the eventual v2 Fiat-Shamir transcript.

Statistical and assembly tests can find leaks but cannot establish their
absence. Cache, speculative-execution, scheduler, physical, and shared-host
attacks remain deployment concerns.
