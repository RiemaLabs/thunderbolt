# Protocol v2 capacity differential review

## Executive summary

| Severity | Unresolved |
| --- | ---: |
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 0 |

**Overall change risk:** High. The change modifies consensus-visible resource
limits, public decoding, persisted channel state, ABCI admission, and Ledger RPC
request sizes.

**Recommendation:** Approve the scoped capacity change. Do not activate the v2
proof path until the separately documented 3072-bit Paillier backend and role
integration gates are complete.

The review found two Medium issues during development. Both were fixed before
commit: version-two capacity is now carried by a distinct `ArtifactV2` type, so
the version-one one-MiB boundary remains unchanged; and snapshot/Invoice JSON
decoding now stops at count, duplicate-key, per-event, and cumulative byte
bounds during deserialization rather than after building an unbounded map.

## What changed

**Baseline:** `bbd1376` (`feat: add cometbft rpc transport`)

**Scope:** 27 implementation, documentation, and test files across
`thunderbolt-ledger`, `thunderbolt-protocol`,
`thunderbolt-ledger-app`, `thunderbolt-ledger-abci`,
`thunderbolt-ledger-rpc`, `thunderbolt-holder-node`,
`thunderbolt-committee-node`, `thunderbolt-ownership`, and supporting docs and
tests, plus this review report.

The principal resource contract is:

| Boundary | Limit |
| --- | ---: |
| One v2 artifact | 2 MiB |
| One canonical v2 event | 4 MiB / 2 - 2 KiB |
| One signed proposal or Ledger RPC request | 4 MiB |
| Pending Invoice canonical bytes | 8 MiB |
| Retained channel state | 11 MiB |
| Canonical snapshot | 12 MiB |
| ABCI query response | 24 MiB |
| Aggregate block event bytes | 8 MiB |
| Aggregate block transaction bytes | 24 MiB |

The exact 256-member threshold fixture measures 212,661 bytes for the Recipient
message, 1,491,757 bytes for the threshold message, 1,705,843 bytes for the
canonical Invoice event, 3,413,182 bytes for the signed proposal, and 3,413,339
bytes for the correlated Ledger RPC request.

## Resolved findings

### Medium: global artifact widening changed the version-one contract

The initial draft raised the shared `Artifact` maximum from one MiB to two MiB.
That type is also used by the shipped version-one reducer, storage, verifier, and
node, whose HTTP body defaults remain one MiB. It therefore changed a stable v1
construction and storage boundary while claiming a v2-only capacity fix.

The final change restores `MAX_ARTIFACT_BYTES` to one MiB at
`crates/thunderbolt-protocol/src/identifiers.rs:18` and introduces the distinct
`ArtifactV2`/`MAX_ARTIFACT_BYTES_V2` boundary at
`crates/thunderbolt-protocol/src/v2/types.rs:25-50`. A compile-fail type test and
v1 maximum-plus-one regression prevent accidental reinterpretation.

### Medium: snapshot decoding allocated before cumulative validation

The initial draft retained derived `Deserialize` for `ChannelSnapshotV2` over a
plain `BTreeMap`. A direct decoder could allocate arbitrary map entries before
the 32-Invoice and eight-MiB checks ran.

The final implementation uses a private map visitor at
`crates/thunderbolt-protocol/src/v2/types.rs:681-735`. It rejects the 33rd key
before decoding its value, rejects duplicate keys before decoding the duplicate
value, checks each Invoice's canonical aggregate while parsing its fields, and
stops once the pending canonical total exceeds eight MiB. The completed
snapshot is then checked against the retained-state budget before release.

## Adversarial analysis

The relevant attacker is an authenticated proposal submitter able to construct
validly signed but adversarially large v2 payloads, or an untrusted transport
peer able to return malformed snapshot JSON.

The reviewed attack cases were:

1. Submit the maximum 256-member threshold package. It now fits the v2 artifact,
   event, signed-proposal, ABCI, and RPC boundaries with measured headroom.
2. Submit one byte beyond the event boundary. Canonical event construction
   rejects it before admission.
3. Accumulate five maximum threshold Invoices. The fifth is rejected before
   external proof work or persistence by the eight-MiB pending budget.
4. Combine large Open/Transfer artifacts with pending Invoices. The eleven-MiB
   retained-state budget prevents a reachable snapshot from exceeding the
   twelve-MiB canonical and twenty-four-MiB query envelopes.
5. Send duplicate or more than 32 pending Invoice map keys. The bounded visitor
   rejects them during decode.
6. Run validators with different compiled limits. Every consensus-affecting
   constant is included in `ConsensusProfileV2` at
   `crates/thunderbolt-ledger-abci/src/lib.rs:315-339`, so mismatched binaries
   derive different profiles and refuse the deployment.

No change removes actor authentication, proof admission, request idempotency,
block ordering, or prior state validation.

## Test coverage

The review verified:

- exact 256-member wire, event, signed proposal, RPC request, and snapshot sizes;
- exact event maximum and one-byte-over rejection;
- four maximum pending Invoices accepted and the fifth rejected;
- exact retained-state boundary and one-byte-over rejection;
- snapshot restart rejection after durable state tampering;
- v1 artifact boundary preservation and v1/v2 type separation;
- snapshot count, duplicate-key, per-Invoice, and cumulative decode failures;
- consensus-profile golden and resource-policy mutation;
- ABCI maximum transaction admission;
- existing Ledger signatures, hashes, Merkle proofs, finality, history, and
  canonical RPC round trips.

Independent rerun evidence on the final working diff:

- `thunderbolt-ledger`: 13 tests passed;
- `thunderbolt-ledger-abci`: 32 tests passed; the external four-validator live
  gate remained ignored;
- `thunderbolt-ledger-app`: 16 tests passed;
- `thunderbolt-ledger-rpc`: 28 tests passed;
- `thunderbolt-protocol`: 50 unit/property tests and one compile-fail doctest
  passed.

Strict Clippy, rustdoc warnings-as-errors, formatting, diff checks, and the
locked all-workspace/all-target/all-feature compile gate were also reported
green. The independent review reran the five critical packages successfully;
the first locked invocation was invalidated by a concurrent new-crate manifest,
so that rerun used the same locally resolved dependency graph offline.

## Blast radius and historical context

The change affects 39 `EVENT_BYTES_MAX` references across 12 Rust files, 17
signed-proposal-cap references across seven files, and 50
`ChannelSnapshotV2` references across 13 files. All production callers in that
one-hop surface were compiled and their package tests ran.

The original event cap was introduced with `643a6af` (`feat: add ledger v2
contract`). The original shared artifact cap was introduced with `8401d4d`
(`feat: add reference node`). Neither limit originated in a vulnerability-fix
commit. The final design changes only the v2 capacity boundary and retains the
v1 limit.

## Remaining integration requirements

- The production CometBFT configuration must match the four-MiB single-
  transaction and twenty-four-MiB block policy before readiness.
- A future base64 JSON-RPC broadcast adapter needs its own pre-allocation body
  cap for encoded transaction expansion.
- The Committee finalized-evidence API still duplicates full executed blocks;
  it requires the separately tracked compact block-commitment redesign rather
  than a much larger body limit.
- Raw network transports must enforce their outer byte caps before JSON parsing;
  semantic visitors do not replace transport-level framing limits.

## Methodology

**Strategy:** Focused high-risk differential review.

The review read every production diff, inspected the baseline and Git history
for removed validations, counted transitive call sites, traced event bytes into
signed proposals, ABCI blocks, persisted snapshots, and RPC envelopes, and
constructed concrete maximum and over-limit attack scenarios. Tests and docs
were surface-reviewed; consensus, reducer, decoder, and transport-bound changes
received line-by-line review.

**Confidence:** High for the scoped capacity and decoding changes. This is not a
cryptographic proof audit, CometBFT consensus audit, or production approval for
the complete Thunderbolt deployment.
