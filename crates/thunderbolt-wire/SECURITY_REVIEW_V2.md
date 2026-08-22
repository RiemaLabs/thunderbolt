# Protocol v2 wire differential security review

## Executive summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

**Overall change risk:** High, because this code parses unauthenticated proof material and controls entry to cryptographic code.

**Recommendation:** Approve the raw wire-format change. Do not activate protocol-v2 proof verification in production. The compiled backend cannot represent the required 3072-bit Paillier arithmetic and all conversion and verification calls intentionally fail closed.

The review found no unresolved code finding in the wire-only scope. It confirmed that version 1 retains its prior JSON behavior and canonical hashes, version 2 cannot downgrade to the legacy profile, and attacker-controlled 384-byte keys reach the core backend gate before key construction.

## What changed

**Baseline:** `f7a23d7` (`feat: add Paillier profiles`)

**Scope:** `crates/thunderbolt-wire` only

| Area | Change | Risk |
|---|---|---|
| Raw values | Exact 384-byte modulus/nonce, 768-byte ciphertext, and 81-byte response types | High |
| Public messages | Invoice, Transfer, RecipientShare, and ThresholdRefresh v2 envelopes | High |
| Binding | Mandatory production profile plus full `OperationBindingV2` | High |
| Threshold | Exact ordered roster and deterministic package-intent binding | High |
| Codec | Private bounded DTOs and V2-only compact canonical JSON enforcement | Medium |
| Compatibility | V1 JSON and digest golden tests | Medium |

The implementation adds nine source/test files and modifies four existing wire files. Before this report, the diff contained approximately 2,960 added and 14 moved or removed lines. The only removed executable code was an exact relocation of `OperationBindingV2` canonical field appends into a private helper; the existing binding golden tests passed.

## Security findings

No Critical, High, Medium, or Low finding remains in the reviewed diff.

### Backend blocker, not a finding

Core proof structs require `libpaillier::EncryptionKey` and `BigNumber`. The compiled U4096 backend cannot construct a 3072-bit key because key construction computes a roughly 6144-bit `N²`, and it cannot hold a 768-byte ciphertext. V2 wire values therefore remain raw.

`decode_key_v2` calls the core raw-profile decoder at `src/v2_values.rs:157`. Core rejects `ProtocolV2Production3072` before `BigNumber::from_slice` or `EncryptionKey::from_n`. Invoice, Transfer, RecipientShare, and ThresholdRefresh conversions call this ingress before constructing typed Paillier fields at `src/invoice_v2.rs:286`, `src/transfer_v2.rs:312`, `src/threshold_v2.rs:486`, and `src/threshold_v2.rs:847`.

No 2048-bit fallback exists. A focused regression test supplies legacy typed material to v2 egress and confirms fail-closed behavior without panic at `tests/v2_public_codec.rs:78`.

### Transcript scope, not a finding

The Recipient proof remains the implemented `tb/share` transcript. A v2-only derived Fiat-Shamir context now commits the stable channel context, mandatory profile, complete operation, and expected step. Recipient and VESS proofs additionally share one context that commits the package id and ordered roster commitment. The two-message threshold package also binds the Recipient statement, distribution, and public points at the wire and package-digest boundary. It is not represented as the paper's exact `R_inv^thr` transcript. The source and README state this limitation explicitly.

### Cross-layer size follow-up

The maximum 256-member topology fits the 2 MiB wire-message limit, but it cannot enter the current Ledger stack. With maximum identifiers, vout, step, and threshold, the locked measurements are 212,661 bytes for wrapped RecipientShare, 1,491,757 bytes for wrapped ThresholdRefresh, 1,705,843 bytes for the canonical Invoice event, 3,413,182 bytes for signed-proposal JSON, and 3,413,339 bytes for the Ledger-RPC request.

At the time of this wire-only review, these exceeded the 1 MiB Artifact,
256 KiB event, and 2 MiB RPC request limits. The coordinated follow-up now uses
2 MiB `ArtifactV2` values without changing v1's 1 MiB `Artifact`, a
2 MiB-minus-2 KiB event limit, 4 MiB signed/RPC requests,
and consensus-bound pending, retained-state, snapshot, block, and query
relationships. The wire format keeps the protocol's 256-member topology rather
than silently shrinking it to match an obsolete transport limit. Production
proof activation remains independently blocked on the Paillier backend.

## Adversarial analysis

| Attacker action | Intended impact | Result |
|---|---|---|
| Submit a 384-byte modulus that would panic `EncryptionKey::from_n` | Remote process crash | Core profile gate returns before construction |
| Replace the production profile with legacy 2048 | Parameter downgrade | Closed profile enum and exact widths reject the message |
| Deserialize through a framework or reader | Bypass total-size and canonical checks | Public v2 semantic/raw/profile types have no Deserialize; only the slice-based private-DTO decoder exists |
| Reorder JSON keys or add alternate formatting | Produce a second accepted encoding | V2 trust-boundary decode requires exact compact canonical JSON |
| Mix a Recipient proof with another refresh package | Apply the wrong refresh | Operation, package ID, roster, anchor, and delta equality checks reject it |
| Change invoice ID, profile, expected step, roster, epoch, outpoint, or network | Replay across proof context | Domain-separated Fiat-Shamir context changes or exact-match validation fails |
| Supply 257 committee members | Allocation or verification denial of service | Private bounded sequence visitor stops at the 257th entry |
| Supply arbitrary malformed bytes | Trigger an unchecked panic | 96-case no-panic property passes; total input remains bounded at 2 MiB |

The external attacker model is an unauthenticated peer able to send arbitrary bytes to a service that uses `decode_public_message_v2`. No privileged state or valid proof is assumed.

## Test coverage

| Invariant | Evidence |
|---|---|
| V1 JSON and canonical digest unchanged | `tests/v1_golden.rs:8` |
| Existing v1/v2 binding hashes unchanged | Existing 11-test `binding_v2` suite |
| All four v2 message variants round-trip | `tests/v2_public_codec.rs` |
| Production profile is mandatory | Missing- and cross-profile tests |
| Raw ingress never panics or falls back | `tests/v2_public_codec.rs:78` |
| Operation, step, roster, package, and point tampering fails | Focused tamper test |
| Maximum 256-member roster succeeds; 257 fails | Maximum-boundary test |
| Derived Invoice, Transfer, and threshold proof contexts are stable | Three golden context vectors |
| Maximum topology cross-layer sizes stay explicit | Exact five-size transport regression |
| Decoder round-trip and no-panic properties | Two properties, 96 cases each, in `tests/v2_properties.rs` |

The complete wire suite passed 25 tests plus four compile-fail doctests. Strict all-target Clippy and warnings-as-errors rustdoc passed. Direct wire rustfmt and diff checks passed.

## Blast radius

| Interface | Call sites or implementations | Assessment |
|---|---:|---|
| `from_json_slice` | Existing call sites only | Low; implementation and V1 behavior are unchanged |
| `decode_public_message_v2` | New network ingress | High; owns the only public v2 decode path |
| `ValidateWire` | Existing plus new v2 implementations | Medium; trait API is unchanged |
| `OperationBindingV2` canonical encoding | Existing public digest plus four new envelope families | High; byte sequence is unchanged and golden-tested |
| V2 conversion and verification | New API only | Low current runtime reach; backend always rejects |

## Historical context

The baseline binding received prior security hardening in `4c38a97` and Bitcoin network/genesis validation in `3c51f73`. This diff does not remove those checks. The canonical-append helper preserves every field and the existing binding suite passed unchanged.

No removed line originated in a prior vulnerability fix. No previously removed unsafe construction path was reintroduced in the wire crate.

An independent focused re-review examined the final stable working diff after the proof-context, serde-sealing, and cross-layer-size corrections. It reported no remaining Critical, High, or Medium finding in the wire scope and independently reproduced the focused tests, two 96-case properties, four compile-fail doctests, strict Clippy, formatting, diff checks, and all five maximum-topology size values.

## Recommendations

### Blocking production activation

- Adopt and audit an approved arbitrary-precision Paillier backend before enabling v2 conversion or verification.
- Re-run real 3072-bit invoice, transfer, share, and threshold proof vectors after that backend exists.
- Treat an exact `R_inv^thr` transcript as a separately versioned cryptographic change if implemented.
- Keep the coordinated Ledger, ABCI, RPC, storage, and consensus size profile
  locked to the maximum-topology regression.

### Before integration

- Make the trusted verifier compare the full v2 envelope or canonical digest, not an extracted proof alone.
- Keep `decode_public_message_v2` as the only v2 network trust-boundary decoder.
- Require the RecipientShare and ThresholdRefresh package pair to pass `validate_threshold_package_v2` before persistence or state transition.

## Methodology and limitations

**Strategy:** Deep review of the small, high-risk wire scope.

The review compared the working diff with baseline, read all new source and tests, inspected prior binding-security commits, mapped conversion call order into core, counted public codec blast radius, searched for panic and secret-field paths, and exercised concrete malformed-input and mix-and-match scenarios.

The review does not validate Paillier arithmetic, proof soundness, a deployed verifier, transport authentication, or consensus integration. Real 3072-bit execution is unavailable by design, so review confidence is high for parsing, binding, downgrade resistance, and fail-closed control flow, but unavailable for cryptographic execution.
