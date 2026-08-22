# Signing Protocol v2: design decision and release blocker

Status: **BLOCKED - cryptographic design review required**

Decision date: 2026-08-22

Implementation authorization: **none**

This document answers one narrow release question: can Bitcoin Thunderbolt instantiate finalization by applying standard FROST directly to the Holder plus a `t`-of-`n` Threshold Committee?

The answer is **no**. The paper gives the intended access policy and the additive correctness equation, but it does not give a deployable BIP340/BIP341 signing protocol for that policy. Implementing the formulas as if they were standard FROST would be an unreviewed protocol construction.

No production or mainnet implementation may start from this document. It records the evidence, the missing choices, and the gates needed to turn the research construction into an auditable protocol.

## Decision

Thunderbolt finalization has the access structure

```text
current Holder AND at least t members of the bound Committee epoch.
```

The current Holder owns an independent scalar `x_s`. The Committee owns a Shamir-shared scalar `y_s`, with member shares `y_s(i)`. For a participating Committee set `S`, `|S| >= t`, the intended reconstruction weights are

```text
w_H = 1
w_i = lambda_i(S), i in S
x_s + sum_i(lambda_i(S) * y_s(i)) = x_s + y_s.
```

This is a linear secret-sharing access structure with a mandatory Holder row and a threshold Committee branch. It is not the threshold structure specified by [RFC 9591 FROST](https://www.rfc-editor.org/rfc/rfc9591.html). RFC 9591 assumes that every signer holds `f(i)`, a Shamir share of one group secret `f(0)`, and applies the FROST interpolation coefficient to every signing share. A `(t+1)`-of-`(n+1)` FROST group would not make the Holder mandatory whenever `t+1` Committee members exist. Assigning coefficient `1` to the Holder while separately applying Committee Lagrange coefficients changes the access structure and falls outside the RFC and the original [FROST security proof](https://cypherpunks.ca/~iang/pubs/frost-sac20.pdf).

The Committee can use FROST-style threshold machinery internally, but combining that logical Committee signer with the independent Holder is a new composed protocol. Its concurrent unforgeability, rogue-key resistance, nonce security, identifiable-abort behavior, and BIP340 compatibility require a separate proof and specification.

There is a second independent blocker. RFC 9591's `FROST(secp256k1, SHA-256)` ciphersuite uses 33-byte compressed points and its own `FROST-secp256k1-SHA256-v1` hash-to-field challenge. It does not produce the x-only, even-Y, `BIP0340/challenge` signature required by [BIP340](https://github.com/bitcoin/bips/blob/7fe0b034ec967b52a5a28276419117326df93263/bip-0340.mediawiki). RFC 9591 cannot therefore be used unchanged for a Taproot key-path spend.

As of the decision date, the [official Bitcoin BIPs repository](https://github.com/bitcoin/bips/tree/7fe0b034ec967b52a5a28276419117326df93263) contains BIP327 MuSig2 but no assigned BIP that standardizes BIP340-compatible FROST signing. Experimental implementations and draft work are not a production protocol dependency.

## Paper boundary

The accepted manuscript reviewed for this decision has SHA-256 `0aebd75635f7c17483df7af5453df44ee3a3d210af4cf0d0c9fe8d9dbd9c23c4`. It establishes the following:

- Section 2.2 describes additive two-party Schnorr signing under `P = (x + y)G`.
- Section 4.2 defines `R_own = {(X; x) : X = xH}`, requires a committed closing request acknowledged by at least `t` Committee members, and requires the Holder and Committee to sign jointly under `P`.
- Section 4.6 states that member `i` contributes the Committee key term `e * lambda_i * y_s(i)` so the Committee terms aggregate to `e * y_s`. It calls this "FROST style" rather than specifying a complete FROST transcript.
- Section 5.1 binds authorization to `ctx = (ctx_id, s, P, X_s, tx)` and requires both accepted ownership evidence and the Committee threshold condition.

The paper does not specify:

- a BIP340-compatible threshold ciphersuite;
- Taproot internal-key and output-key parity handling;
- TapTweak application;
- a unified Holder plus Committee nonce protocol;
- a dual-base `G`/`H` DKG or provisioning ceremony;
- a proof that the Holder's `R_own` witness is the same scalar used in the `G`-base signature share;
- coordinator retry, nonce persistence, or recovery rules; or
- a concrete consensus-final quorum receipt.

Those omissions are protocol-design choices, not implementation details.

## Required Bitcoin key semantics

The paper's `P = (x_s + y_s)G` is the raw aggregate key point. A P2TR output is not locked directly to that raw point. [BIP341](https://github.com/bitcoin/bips/blob/7fe0b034ec967b52a5a28276419117326df93263/bip-0341.mediawiki) requires an x-only internal key and a tweaked output key.

Let

```text
P_raw = (x_s + y_s)G
g_P   = 1 if P_raw has even Y, otherwise -1
P     = g_P * P_raw
p     = xonly(P)
h     = the exact Taproot Merkle root, or the empty byte string
t_tap = int(tagged_hash("TapTweak", p || h))
Q_raw = P + t_tap*G
g_Q   = 1 if Q_raw has even Y, otherwise -1
Q     = g_Q * Q_raw
q     = xonly(Q).
```

Construction must fail if `P_raw` or `Q_raw` is the identity, if either x-only lift fails, or if `t_tap >= n`.

The output script is `OP_1 <q>`. Even when there is no script path, BIP341 still applies the TapTweak with `h` empty. The full output descriptor must freeze `p`, `h`, `t_tap`, `q`, and both parity decisions at Open.

The corresponding effective key-path signing scalar is

```text
d_Q = g_Q * (g_P * (x_s + y_s) + t_tap) mod n.
```

A future protocol must therefore apply the factor `g_Q * g_P` to both the Holder and Committee secret contributions, and add `g_Q * t_tap` exactly once. The aggregate nonce must also be normalized to even Y before computing

```text
e = int(tagged_hash("BIP0340/challenge", xonly(R_even) || q || m)) mod n,
```

where `m` is the 32-byte BIP341 key-path message `hash_TapSighash(0x00 || SigMsg(hash_type, 0))`. A 64-byte witness implies `SIGHASH_DEFAULT`; a non-default hash type must be explicit and appended according to BIP341.

These equations are a correctness target only. They are not a security proof for the Holder-plus-threshold access structure.

## Why the obvious substitutions are unsafe

### Put the Holder into an ordinary FROST group

An ordinary `(t+1)`-of-`(n+1)` group allows any `t+1` participants to sign. It does not require the Holder. Giving the Holder multiple virtual shares changes the corruption model, nonce accounting, and signer-identifier assumptions and is not covered by RFC 9591.

### Run Committee FROST and add a Holder partial signature

Standard FROST computes binding factors, the group nonce, and the challenge using the Committee group public key and the Committee commitment list. Thunderbolt needs a challenge under the final BIP341 output key and a nonce that includes the Holder. Replacing the group key, commitment set, challenge, and final response with Holder-aware values changes the protocol proven by FROST.

### Treat the Committee as one MuSig2 signer

[BIP327 MuSig2](https://github.com/bitcoin/bips/blob/7fe0b034ec967b52a5a28276419117326df93263/bip-0327.mediawiki) is BIP340-compatible and specifies two nonces, key aggregation, tweaks, and parity, but it is `n`-of-`n`, not `t`-of-`n`. Its rogue-key-resistant key coefficients also change the paper's raw invariant from `P = X_G + Y_G` to a coefficient-weighted aggregate. Nesting a threshold signer inside MuSig2 would need a proof that the threshold subprotocol securely realizes one MuSig2 signer under concurrent sessions. That proof does not currently exist for Thunderbolt.

### Apply ROAST immediately

[ROAST](https://eprint.iacr.org/2022/550.pdf) is a robustness wrapper around an underlying semi-interactive threshold signature protocol. It assumes that the underlying scheme is concurrently unforgeable and has identifiable aborts. The unreviewed Holder-plus-Committee composition has established neither property, so ROAST cannot be claimed as a drop-in security upgrade. Once the base protocol is proven, ROAST's coordinator pattern, with at most `n - t + 1` concurrent base sessions, is the appropriate liveness reference.

## Required cross-base consistency

Thunderbolt deliberately uses the independent generator `H` for Holder anchors and VESS commitments, while Bitcoin signing uses `G`. That creates two missing bridges.

### Holder bridge

The paper's `R_own` proves only knowledge of `x_s` such that `X_s = x_s H`. A partial signature under `G` must use the same `x_s`. Before signing, the protocol must establish an equality-of-discrete-log statement of the form

```text
X_s   = x_s H
X_s,G = x_s G
```

with `X_s,G` bound to the fixed aggregate key and Committee group key. The existing `R_own` relation alone does not establish this equality. Publishing or deriving `X_s,G` also exposes `Y_s,G = P_raw - X_s,G`, which the paper intentionally avoids during ordinary transfers. The timing and leakage of this bridge require explicit review.

### Committee bridge

FROST share verification requires `G`-base verification shares `Y_i = y_s(i)G` and group key `Y = y_s G`. Thunderbolt's VESS update is committed in base `H`. A production ceremony must prove that the `G`-base FROST shares and `H`-base update shares contain the same scalar polynomial at Open and after every transfer or resharing event.

At minimum, the reviewed design must include dual-base coefficient commitments and equality-of-discrete-log proofs, or another proven construction with the same guarantee. A member must not be able to update its `H`-side share while retaining a different `G`-side signing share.

## DKG and provisioning decision

RFC 9591 leaves key generation out of scope. Its appendix gives only a trusted-dealer reference flow, which assumes that the dealer deletes the group secret and every generated share. That assumption is not acceptable as the default production ceremony for Thunderbolt.

A production design must provide a reviewed DKG or a separately approved hardware-backed provisioning ceremony with all of the following outputs:

- one immutable Committee descriptor with unique non-zero scalar identifiers, threshold, epoch, suite ID, and operator identity keys;
- a Shamir polynomial with free term `y_0` and one secret share per member;
- `G`-base verification shares and group key;
- `H`-base update commitments;
- public proofs that both bases commit to the same coefficients;
- a joint Open proof that `P_raw`, `X_0`, and the Committee group key are consistent;
- transcript agreement by every member and the initial Holder; and
- a finalized Ledger record and Bitcoin funding-output check before the shares become active.

The ceremony must reject identity Holder, Committee, or aggregate group keys. The normative DKG must also define zero-share and zero-coefficient handling. This release gate is fail closed: an epoch is not activated if any required verification share or coefficient commitment cannot be serialized by the selected ciphersuite. A zero coefficient may be accepted only if the reviewed DKG explicitly defines its identity commitment and proof behavior.

Proactive resharing and Committee rotation must preserve the free term, refresh both bases consistently, advance the Committee epoch, and invalidate the old signing configuration. Until this ceremony is specified and audited, Open and Finalize remain blocked.

## Signing-session requirements

The following is the minimum session schema that a future reviewed construction must bind. It is a checklist, not a frozen hash transcript.

### Intent fields fixed before nonce generation

1. protocol and signing-suite versions;
2. Bitcoin network and genesis hash;
3. deployment ID, Committee epoch, and descriptor digest;
4. Ledger chain ID and finalized authorization entry hash;
5. channel context ID, funding outpoint, and current step;
6. `P_raw`, internal x-only key `p`, internal parity, Merkle root `h`, TapTweak, output key `q`, and output parity;
7. exact compressed `H`, its parameter-suite ID, its deterministic NUMS derivation transcript digest, and the explicit assumption that its discrete logarithm relative to `G` is unknown;
8. exact `X_s,G`, Committee group key `Y`, each selected member identifier, `Y_i`, and `lambda_i(S)` in canonical sorted order;
9. Holder cross-base equality-proof statement and proof digests, plus the dual-base coefficient-commitment and proof-transcript digest for the active Committee state;
10. exact closing transaction digest, input index, sighash type, complete prevout outpoints, amounts, scriptPubKeys, and sequences for every transaction input, plus annex presence and bytes;
11. the 32-byte BIP341 message recomputed from the transaction and the complete prevout and annex data;
12. current anchor `X_s`, `R_own` statement digest, proof digest, and verified-ownership capability digest;
13. finalized quorum-receipt digest and sorted acknowledgement member IDs;
14. exact Holder identity and sorted Committee signing subset;
15. monotonic attempt number and coordinator identity.

The canonical intent digest must use a new, reviewed domain and length-prefixed encoding. Reusing the paper's proof tags, RFC 9591 ciphersuite tags, BIP340 nonce tag, or BIP327 tags for this purpose is forbidden.

A descriptor digest is sufficient only after the descriptor's canonical schema is frozen and commits to `H` and its derivation, `Y`, every member identifier and `Y_i`, threshold, epoch, both-base commitments, and proof-suite IDs. Signers must reconstruct and compare that digest rather than trust a coordinator-supplied label.

Signers must recompute the BIP341 message themselves. For default or other non-`ANYONECANPAY` modes, `SigMsg` commits to the prevouts, amounts, scriptPubKeys, and sequences of all inputs, as well as annex data when present. A coordinator-supplied 32-byte `m` is never sufficient. A future profile may instead require a one-input, no-annex closing transaction, but that restriction must be enforced when constructing and validating the transaction, not assumed by the signer.

### Commitments fixed before signature shares

Every logical contributor, including the Holder, must reserve two fresh secret nonces and publish two public commitments. The second-round package must add the sorted complete commitment list to the intent fields. Binding factors must cover the final BIP340 output key, the BIP341 message, the exact signer set, and every Holder and Committee commitment. The signer set and package bytes must be identical for every participant.

RFC 9591's hiding and binding nonce design and BIP327's BIP340-compatible two-nonce session are reference patterns. Neither can be copied partially. The eventual proof must cover the exact combined transcript.

For review, the algebraic correctness target is as follows. It is not an approved signing protocol. For each logical signer `j`, let the two secret nonces be `(d_j, b_j)`, their points be `(D_j, B_j)`, and `rho_j` be the binding factor derived from the complete second-round package and signer identifier. Define

```text
k_j   = d_j + rho_j*b_j
R_raw = sum_j(D_j + rho_j*B_j)
g_R   = 1 if R_raw has even Y, otherwise -1
R     = g_R*R_raw
a_H   = g_Q*g_P
a_i   = g_Q*g_P*lambda_i(S).
```

Every `D_j` and `B_j` must be a canonical, on-curve, nonidentity point. If any commitment is invalid or `R_raw` is the identity, the entire attempt aborts and every contributor burns both nonce scalars reserved for that package. No BIP327-style fallback that substitutes `G` for an identity aggregate nonce may be imported without a security proof for this exact access structure.

The candidate partial-response equations are

```text
z_H = g_R*k_H + e*a_H*x_s
z_i = g_R*k_i + e*a_i*y_s(i), i in S
z   = z_H + sum_i(z_i) + e*g_Q*t_tap.
```

Partial verification would target

```text
z_H*G = g_R*(D_H + rho_H*B_H) + e*a_H*X_s,G
z_i*G = g_R*(D_i + rho_i*B_i) + e*a_i*Y_i.
```

These equations produce the desired final BIP340 verification equation if every cross-base and parity premise is true. That proves only algebraic correctness. It does not establish unforgeability, safe binding-factor derivation, or concurrent-session security.

### Nonce state and retry rules

- Reserve and durably fence a nonce pair before returning its commitment.
- Bind a pair to one attempt and one exact signing-package digest.
- Burn the pair on signature-share creation, abort, timeout, coordinator change, signer-set change, commitment-list change, message change, or ambiguous transport outcome.
- Any participant failure that prevents the package from completing invalidates that package. Every contributor must burn its reserved pair before any new subset or attempt starts.
- Never copy a secret nonce into a backup or another process.
- An already persisted signature share may be retransmitted idempotently for the exact package; it must never be recomputed with the old nonce.
- A recovered process must burn every unresolved reservation before joining a new attempt.
- The independent rollback floor must prevent an older vault backup from reviving a nonce reservation or consumed nonce.

RFC 9591 requires one-time nonces and warns that reuse enables complete key recovery. It also does not provide robustness. A simple retry must use a new attempt and new nonces. A ROAST-style coordinator may be considered only after the base construction has a concurrent-security proof and identifiable aborts; each concurrent ROAST session needs disjoint nonce pairs.

## Authorization and quorum receipt

No signer may accept a coordinator's unsigned claim that finalization was authorized. Before round two, each signer must externally verify a consensus-final receipt containing:

- the exact Finalize event and canonical closing transaction;
- channel context, step, funding outpoint, complete transaction/prevout/annex data, sighash type, and recomputed BIP341 message;
- `P_raw`, `p`, `h`, TapTweak, and `q`;
- exact `H` derivation and suite, `X_s,G`, Committee `Y`, selected identifiers, `Y_i`, and Lagrange weights;
- the current `X_s`, accepted `R_own` proof binding, Holder equality-proof digest, and active dual-base proof-transcript digest;
- canonical Committee descriptor contents and digest, epoch, and a sorted set of at least `t` acknowledgements;
- Ledger height, consensus time, application hash, committing-header identity, and application-state inclusion proof; and
- the request and entry digests used for idempotent recovery.

The signing Committee subset must be a subset of the acknowledged members in that receipt. The receipt is authorization evidence, not a signature share and not a replacement for BIP340 verification. The completed 64-byte signature must verify under `q` and the exact BIP341 message before it is persisted, released, or broadcast.

## Recovery decision

Recovery cannot broaden the access policy.

| Failure | Required behavior |
| --- | --- |
| Coordinator crashes before aggregation | Resume only by retransmitting already persisted commitments or shares for the exact package. Otherwise start a new attempt and burn all prior nonce pairs. |
| Member crashes before returning a share | Abort the package. Every Holder and Committee contributor burns both reserved nonces before a new subset or attempt. |
| Member crashes after returning a share | Retransmit the identical persisted share only. Never reconstruct the consumed nonce. |
| Vault backup is restored | Verify the external checkpoint floor first and permanently reject every stale session or nonce record. |
| Committee member is replaced | Complete a reviewed resharing or rotation protocol and activate a new finalized epoch before signing. |
| Holder secret is lost | Funds are not recoverable through the key path. |
| Fewer than `t` Committee shares survive | Funds are not recoverable through the key path. |

An alternate recovery spend requires a Taproot script path committed at Open. It cannot be added later because it changes `h`, the TapTweak, and `q`. The paper does not choose a recovery script, delay, emergency key, or governance policy. Production deployment is blocked until that policy is explicitly accepted or operators explicitly accept permanent loss when Holder or threshold key material is unavailable.

## Exact vector manifest

The implementation gate must vendor the following primary vectors at the exact Bitcoin BIPs repository commit `7fe0b034ec967b52a5a28276419117326df93263`:

| Source | Required file | SHA-256 |
| --- | --- | --- |
| BIP340 | `bip-0340/test-vectors.csv` | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` |
| BIP341 | `bip-0341/wallet-test-vectors.json` | `403e19fb81dd1f31e745699216308f61fb403774b2aafa87b631b8f7c042d37f` |
| BIP327 | `bip-0327/vectors/sign_verify_vectors.json` | `692eecc101f3e515c29137f05031935e1210d2a01bab91e674eb0234f095c15c` |
| BIP327 | `bip-0327/vectors/tweak_vectors.json` | `80ce6385ce062644ad1f4edcb9d4797f70ddb0b74769e4099f51b3c9e6ab4aff` |

The Committee-only primitive must also reproduce RFC 9591 Appendix E.5 from `rfc9591.txt`, SHA-256 `fd8366795c833348d552e6a4141e8bf413310940fd50af484283207716d1a6a7`. Passing that vector demonstrates RFC FROST interoperability only. It does not demonstrate BIP340 compatibility or validate the Thunderbolt composition.

The future Thunderbolt vector set must contain these exact cases:

### `TB-SIGN-001`: asymmetric reconstruction

Use secp256k1 order

```text
n = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
x = 5
y = 7
f(z) = 7 + 11*z
S = {1, 3}
y(1) = 18
y(3) = 40
lambda_1 = 7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a2
lambda_3 = 7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
```

Expected scalar checks:

```text
lambda_1*18 + lambda_3*40 mod n = 7
x + lambda_1*18 + lambda_3*40 mod n = 12
```

The Committee-only result `7` must not authorize a signature under the target key for scalar `12`. Holder plus one Committee member must also fail when `t = 2`.

### Required negative and state vectors

- `TB-SIGN-002`: each BIP340 internal-key parity and BIP341 output-key parity branch, with empty and non-empty Merkle roots;
- `TB-SIGN-003`: wrong or duplicated TapTweak contribution;
- `TB-SIGN-004`: `R_own` witness valid under `H` but mismatched to the `G`-base Holder share;
- `TB-SIGN-005`: wrong `H` derivation transcript, Holder `G`/`H` mismatch, or one Committee `G` verification share mismatched to its `H` update commitment;
- `TB-SIGN-006`: every intent field and every nonce commitment mutated one at a time;
- `TB-SIGN-007`: signer-set reorder, removal, duplication, and round-one/round-two substitution;
- `TB-SIGN-008`: invalid or identity commitment, identity `R_raw`, and nonce reuse after timeout, member failure, coordinator change, crash, backup restore, or ambiguous submission, with every contributor's burn state checked;
- `TB-SIGN-009`: stale, forked, wrong-epoch, and insufficient-ack quorum receipts;
- `TB-SIGN-010`: invalid partial share identification without releasing any honest secret;
- `TB-SIGN-011`: final BIP340 signature accepted by Bitcoin Core regtest, followed by wrong transaction, input index, any input's prevout/amount/scriptPubKey/sequence, annex, output, and sighash rejection;
- `TB-SIGN-012`: ROAST disruption and coordinator replacement, only after the base protocol proof is accepted.

No new golden signature bytes may be declared authoritative until the transcript, BIP340 adaptation, access-structure proof, DKG, and tweak allocation are frozen. At that point, two independent implementations must generate identical vectors and a third implementation must verify them. The vector directory and its checksum manifest must be committed before production code is merged.

## Audit gates

All gates are mandatory:

1. **Construction proof**: peer review of concurrent unforgeability for the mandatory-Holder plus threshold-Committee access structure, including malicious coordinator and rogue-key analysis.
2. **Bitcoin profile**: a byte-level BIP340/BIP341 specification for x-only keys, both parity corrections, TapTweak, sighash encoding, nonce binding, partial-share verification, and final serialization.
3. **Cross-base proof**: reviewed equality guarantees between all `G`-base signing material and `H`-base ownership/update material.
4. **Key ceremony**: reviewed DKG or approved provisioning, authenticated transcript agreement, complaint handling, resharing, rotation, and key erasure boundaries.
5. **Authorization**: externally verified quorum receipt and exact `R_own` binding before any signature share.
6. **Nonce safety**: durable reserve-use-burn state machine, crash and rollback-floor tests, concurrency tests, and fault-injection review.
7. **Robustness**: proof that any ROAST wrapper assumptions hold for the exact base protocol, plus bounded-session and denial-of-service tests.
8. **Implementation review**: constant-time secret operations, zeroization, HSM interface review, memory-safety analysis, and independent cryptographic audit.
9. **Interoperability**: all pinned primary vectors and `TB-SIGN-001` through `TB-SIGN-012` pass in at least two independent implementations.
10. **Bitcoin integration**: clean regtest key-path funding and spend, restart and reorg campaigns, signet soak, and explicit mainnet refusal until the external audit is closed.

## Unblocking decision

This blocker can be closed only by one of the following reviewed choices:

1. specify and prove a BIP340-compatible FROST variant over the Thunderbolt linear access structure; or
2. specify and prove a composition between a BIP340-compatible threshold Committee signer and a Holder multisignature protocol, while preserving the paper's fixed-key invariant and privacy goals.

The review must select one path, publish the normative transcript and vector set, and resolve recovery policy. Until then, repository code may expose interfaces and regression stubs, but it must not produce or claim production finalization signatures.

## Primary references

- Bitcoin Thunderbolt accepted manuscript, Sections 2.2, 4.2, 4.6, and 5.1.
- [BIP340: Schnorr Signatures for secp256k1](https://github.com/bitcoin/bips/blob/7fe0b034ec967b52a5a28276419117326df93263/bip-0340.mediawiki).
- [BIP341: Taproot SegWit version 1 spending rules](https://github.com/bitcoin/bips/blob/7fe0b034ec967b52a5a28276419117326df93263/bip-0341.mediawiki).
- [BIP327: MuSig2 for BIP340-compatible multisignatures](https://github.com/bitcoin/bips/blob/7fe0b034ec967b52a5a28276419117326df93263/bip-0327.mediawiki).
- [RFC 9591: FROST](https://www.rfc-editor.org/rfc/rfc9591.html).
- [Komlo and Goldberg, FROST](https://cypherpunks.ca/~iang/pubs/frost-sac20.pdf).
- [Ruffing et al., ROAST](https://eprint.iacr.org/2022/550.pdf).
