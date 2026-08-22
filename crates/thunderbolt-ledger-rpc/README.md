# Thunderbolt Ledger RPC v2

This crate defines the versioned control-plane messages shared by Ledger clients and server adapters. It does not open sockets, choose HTTP or gRPC, authenticate peers, execute consensus, or verify a validator quorum.

## Trust boundary

Three results are deliberately different:

1. `AdmissionStatusV2::Accepted` means only that a transport admitted a signed proposal.
2. `ExecutedBlockCommitmentV2`, one exact `ExecutedEntryV2`, and an
   `EntryMerkleProofV2` establish deterministic execution consistency only.
3. `VerifiedFinalizedEntryV2` is issued only after a caller-supplied
   `ExternalFinalityVerifierV2` accepts the compact commitment, exact entry,
   proof, application version, chain, app hash, and opaque consensus receipt.

`FinalityStatusV2::ReceiptAvailable` does not itself grant finality. It says that bounded receipt bytes are available for verification. There is no boolean `verified` field and no public constructor for the verified capability.

## Methods

| Method | Request | Response | Meaning |
| --- | --- | --- | --- |
| `submit_proposal` | Ledger chain plus `SignedProposalV2` | Proposal, entry, and request digests plus admission status | Admission only |
| `channel_status` | Ledger chain plus stable `ChannelContextIdV2` | Full channel binding, executed location, entry hash, state hash, canonical snapshot bytes, receipt availability | Materialized state observation |
| `request_status` | Chain, channel context, participant, and request digest | Unknown, admitted, executed, or a compact finality-carrying entry bundle | Exact idempotency-key lookup |
| `history` | Channel context, bounded page size, and global execution cursor | Bounded executed-metadata projection plus an optional next cursor | Ordered pagination |
| `execution_range` | Exact chain/start/predecessor cursor, whole-block count, and byte cap | The exact globally contiguous whole blocks plus the mandatory next cursor | Execution-only range evidence |
| `entry_location` | Exact chain, channel, entry hash, inclusive height, and app hash | The first execution location through that checkpoint, or `None` | Immutable first-location lookup |
| `rollback_floor_cas` | The floor crate's exact chain-bound `FloorCasRequest` | Transport acceptance, explicit ambiguity, or `CheckpointCasOutcome` plus receipt | Independent rollback checkpoint |

The actor in a proposal is always the BIP340 key, derived participant identifier, and typed role authenticated by `SignedProposalV2`. The RPC schema has no caller-selected actor name and no field for client-supplied verification evidence.

## Canonical envelopes

Requests and responses use compact JSON with a fixed outer `api_version` of `2`. `to_canonical_bytes` emits the only accepted byte representation. `RpcRequestV2::from_canonical_bytes` validates requests. `RpcResponseV2::from_canonical_bytes_for` requires the exact request and returns only `CorrelatedRpcResponseV2`; there is no public raw response decoder. Both paths require exact byte-for-byte re-encoding. The top-level request and response enums deliberately do not implement `Deserialize`; adapters cannot bypass version, body, canonical, or response-correlation checks by handing them directly to a web framework. Unknown fields, duplicate fields, whitespace variants, reordered fields, uppercase hexadecimal, trailing bytes, and unsupported versions fail closed.

Public request payloads, response payloads, snapshots, consensus receipts, ambiguity tokens, floor wrappers, and RPC digest types do not implement `Deserialize`. Private wire DTOs are reached only after the complete request or response passes its outer body-size check, then apply their tighter field and hexadecimal bounds. Frameworks therefore cannot select a nested public type as an alternate ingress path.

Request digests cover the complete versioned canonical request. Proposal submission independently checks that the outer Ledger chain equals the chain authenticated inside `SignedProposalV2`. The signed proposal's stable channel context commits the complete deployment and committee binding.

Request-correlated decoding proves canonical shape and exact request matching, not server authenticity. A client must still apply external finality verification wherever a receipt is present.

A channel-status response echoes the complete `ChannelBindingV2`. Decoding fully parses the bounded canonical state through EOF, reconstructs a validated `ChannelSnapshotV2`, compares the embedded binding digest and Ledger chain, derives the requested context from the binding, and checks the response entry hash against the snapshot head.

The rollback-floor RPC wrapper transports `FloorCasRequest::canonical_bytes()` and its existing request digest. Decoding reconstructs the floor crate's `FloorLedgerChainId`, complete `VaultIdentity`, expected checkpoint, and exact-next checkpoint. It does not define a second checkpoint identity or CAS transition.

## Bounds

- Request envelope: 4 MiB
- Response envelope: 32 MiB
- Canonical snapshot bytes: 12 MiB
- Opaque consensus receipt: 1 MiB
- History page: 64 metadata records
- Execution range: exactly 1 to 64 whole blocks and at most 23 MiB for the canonical block array
- Ambiguity token: 16 to 256 bytes

Length checks happen before JSON parsing. Nested Ledger, protocol, wire, floor, and keystore constructors enforce their own tighter bounds.
The 12 MiB snapshot cap is paired with an 8 MiB pending-Invoice sub-budget and
an 11 MiB cumulative retained-state budget in the protocol reducer. A maximum
256-member Invoice request is 3,413,339 bytes, and the maximum-field event limit
retains an explicit metadata reserve below the 4 MiB request ceiling.

## Pagination

`HistoryCursorV2` is a global deterministic execution position:

- exact Ledger chain;
- next block height;
- next block index; and
- application hash immediately before that height.

Height one uses the zero application hash. Later heights require a non-zero predecessor application hash. Returned channel metadata is strictly ordered and an optional continuation cursor must move forward. Every page echoes the digest of the complete history request, so even an empty page cannot be replayed across a different chain, channel, cursor, or limit. The cursor, including its predecessor application hash, is an untrusted continuation hint that the server must revalidate against committed state. Completeness still requires a trusted or proven server view. A cursor is not a consensus receipt.

`ExecutionRangeCursorV2` is separate from channel-filtered history. It contains
the exact Ledger chain, next whole-block height, and predecessor app hash. An
execution-range response must contain exactly the requested positive block
count, including empty blocks, and a mandatory cursor immediately after its
last block. It cannot end early, return an empty page, omit an empty block, or
end midway through a block. Internal successors recheck height, app-hash, and
monotonic-time continuity. The complete request digest binds chain, cursor,
count, and byte cap.

An entry-location request binds an inclusive historical height and the exact
application hash at that height. A `None` response is therefore not portable
to another checkpoint. A returned position remains deterministic execution
evidence only; the client must fetch and match the pointed block and establish
consensus finality separately.

## Adapter requirements

A production server adapter must authenticate clients, set deadlines and body limits before allocation, preserve explicit ambiguity for potentially committed writes, and avoid retrying non-idempotent submissions as if they had failed cleanly.

A production finality verifier must pin its trust root and verifier profile, validate the intended Ledger or floor chain, prove validator quorum or light-client continuity, bind the adjacent committing header and app hash, verify application-version-two inclusion for the exact claim, and persist trusted-header progress safely. Capability issuance first requires exact equality between the receipt's profile ID and the verifier's declared profile. These consensus details are deployment design, not claims made by the research paper or by this codec.

Finalized entry bundles never carry or duplicate a full `ExecutedBlockV2`.
They contain only its validated compact commitment, one exact entry, the entry's
ordered Merkle proof, and the opaque receipt. Bundle construction and decode
re-derive entry metadata from the signed proposal and verify inclusion. There is
no raw full-block constructor or compatibility fallback. The external verifier
must authenticate every commitment field, especially the application hash,
against the receipt before a finality capability is issued.
