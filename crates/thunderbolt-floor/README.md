# Bitcoin Thunderbolt external rollback floor

`thunderbolt-floor` is the client-side adapter between the encrypted participant
vault and an independent consensus Ledger. It stores no secrets and provides no
local-file floor.

The adapter binds every operation to the complete `VaultIdentity` and exact
`VaultCheckpoint`, plus the configured external floor Ledger chain ID.
Initialization is only `None -> revision 0`; every later CAS is the exact next
revision with a different encrypted-state digest. A copied vault that produces
another checkpoint at the same revision conflicts, and a request cannot be
replayed onto another floor chain under the same digest.

Transport is not trusted. `LedgerFloorTransport` returns only
`UnverifiedLedgerResponse`. `LedgerFinalityVerifier` must validate a validator
quorum certificate or trusted light-client header chain, the configured
consensus chain, canonical application inclusion, and the exact floor
state-machine result. The adapter then independently checks the request digest,
complete vault identity, operation kind, and returned checkpoint.

The verifier must advance a monotonic trusted header and reject otherwise valid
historical receipts below that trusted state. Replaying an old finalized CAS
receipt is not evidence of the current floor.

Ambiguous submissions use an opaque transport token. Resolution must be
causally ordered and prove the finalized result of that exact CAS; an ordinary
read that could finalize before the pending write is not sufficient.

## Deployment status

The server side is implemented by `thunderbolt-floor-app`,
`thunderbolt-floor-abci`, and `thunderbolt-floor-node`. This client-side adapter
is not deployable by itself: version 1.0 does not include a concrete
authenticated `LedgerFloorTransport` or a `LedgerFinalityVerifier` that binds
finalized Floor results to the configured chain. Deployments provide those
integrations explicitly; test doubles do not cross this boundary.
