# Bitcoin Thunderbolt Committee Node

This crate is the restart-safe service boundary for one independently operated
Committee member. It combines the one-member cryptographic engine and encrypted
checkpoint-fenced keystore with a bounded SQLite inbox, acknowledgement outbox,
and finalized Ledger cursor.

It consumes exact `SignedProposalV2`, `ExecutedBlockV2`, and
`EntryMerkleProofV2` values. Those prove authentication and deterministic
execution only. An operator-supplied `LedgerFinalityVerifier` must authenticate
a CometBFT quorum or light-client receipt before an item enters the inbox. The
crate ships only a verifier that fails closed.

The verifier must issue one durable paired capability proving the Invoice and
Transfer share a finalized ancestry and strict total order. Its refresh ordinal
and prior-refresh hash must come from Ledger application state committed by the
verified app hash. The service stores only this bounded attestation, not an
expiring raw light-client receipt, and authenticates it again on restart.
The verifier profile ID, covering the Ledger app version, Comet trust policy,
authenticator domain, and attestation key, is immutable in node configuration,
SQLite identity, and every capability. A different per-call verifier is rejected
before it can verify or mutate state.

Schema-v1 databases with pending inbox work are rejected before any migration
or profile backfill. They require an offline migrator that authenticates every
legacy attestation under the selected pinned profile. The runtime never guesses
that binding or marks such a database schema v2.

The SQLite cursor advances only for the exact next refresh ordinal whose prior
refresh hash equals the current cursor. Poll batches are sorted by that ordinal;
gaps, forks, backwards positions, and conflicting duplicate requests fail
closed before the cursor changes.

The service rechecks the committed Invoice's Recipient share proof, threshold
distribution, and consumed Transfer package before updating its one local
Shamir share. A crash after the encrypted share update but before SQLite commit
is recovered by deterministic engine replay.

No Committee-authored v2 event currently exists, so update acknowledgements
remain unsigned local outbox records. The shipped signer hook fails closed. The
crate does not implement or claim DKG, FROST signing or aggregation, CometBFT
finality, automatic reorg recovery, mainnet readiness, or Testnet4 support.
