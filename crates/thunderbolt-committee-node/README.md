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

The service rechecks the committed Invoice's Recipient share proof, threshold
distribution, and consumed Transfer package before updating its one local
Shamir share. A crash after the encrypted share update but before SQLite commit
is recovered by deterministic engine replay.

No Committee-authored v2 event currently exists, so update acknowledgements
remain unsigned local outbox records. The shipped signer hook fails closed. The
crate does not implement or claim DKG, FROST signing or aggregation, CometBFT
finality, automatic reorg recovery, mainnet readiness, or Testnet4 support.
