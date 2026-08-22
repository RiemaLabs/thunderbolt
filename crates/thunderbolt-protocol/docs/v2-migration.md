# Version-two migration boundary

Version two is a separate protocol surface. Version-one JSON, reducer behavior,
canonical encodings, and golden hashes remain unchanged. A deployment must not
reinterpret a version-one entry as version two or mix predecessor hashes across
the two histories. There is no automatic in-place migration.

The active v2 path consumes `thunderbolt-ledger`'s BIP340-authenticated proposal
capability and `thunderbolt-wire`'s complete stable channel binding. That binding
includes the protocol suite, Bitcoin network and genesis hash, deployment,
funding outpoint, committee epoch and descriptor digest, and anchor parameter
suite. V1 free-string actors, participant ids, and idempotency keys are not v2
authorization inputs. Actor-scoped request digests provide replay identity. The
Open event fixes the member count and threshold carried in materialized state;
the trusted Open verifier must match that topology to the bound descriptor.

The v2 reducer implements deterministic application rules for a bounded set of
concurrent Invoice events, one selected Transfer, and total-order Finalize. A
valid Finalize abandons outstanding invoices instead of allowing an unrelated
invoice to veto close. If Transfer commits first, later Finalize authorization
is checked against the new Holder. If Finalize commits first, later Transfer is
rejected because the channel is final. A Transfer binds both the Invoice id and
the exact committed Invoice entry hash. It consumes the selected Invoice and
invalidates other invoices proved for the preceding Holder step.

Every Invoice id is single-use for the channel lifetime. Storage must enforce
that indexed fact in the same transaction as reduction. The materialized map is
bounded and is not a substitute for the lifetime uniqueness index. Invoice
expiry is mandatory and subject to a configured maximum lifetime. The entry
budget reserves its last position for Finalize, so Invoice traffic cannot make
the channel uncloseable. Pending state retains the exact authenticated Invoice
payload required by the Transfer verifier.

Ledger block time is positive trusted consensus input, not client evidence. The
reducer accepts time only through a proposal position in a validated pending
block or through recomputed finalized-entry metadata, and it pins one expected
Ledger chain id.
Proofs and the bounded raw closing transaction are untrusted event inputs.
Authentication and cryptographic acceptance arrive through typed trusted
capabilities; serialized events cannot assert a `verified` result. Finalize's
external verifier receives the exact closing transaction together with the
stable context and latest committed Holder state.

Protocol-event bytes have a v2-only canonical encoding embedded exactly in the
signed Ledger proposal. The Ledger entry hash remains authoritative for the
predecessor chain. Materialized state has a separate domain-separated hash.

This module specifies only the implemented application rules. It does not claim
theorem equivalence, UC realization, or completeness with respect to the paper.
