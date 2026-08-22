# Threat model

This threat model follows the accepted Thunderbolt paper and adds the operational risks of a real daemon deployment. It applies to the base protocol. Optional overlays in the paper are outside the `v1.0.0-rc.1` scope.

## Assets

- Holder secrets and credentials
- committee shares and threshold-signing nonce material
- the fixed Taproot lock key and funding UTXO
- the current public anchor and channel sequence
- invoice freshness and uniqueness
- committed Ledger history
- local databases, backups, control credentials, and configuration
- release artifacts and update-signing keys

## Security properties

Ownership security
: Only the current Holder, together with the required committee threshold, can transfer ownership or finalize the channel.

Fixed-key integrity
: Off-chain transfers rotate Holder and committee shares without changing the Bitcoin lock key.

Transfer correctness
: A valid transfer gives the Recipient a usable next-Holder secret and applies the matching committee update.

Liveness
: Transfer and Finalize complete when at least `t` committee members are honest, responsive, and able to reach a Ledger that includes valid entries.

Operational integrity
: A daemon restart, duplicate request, delayed message, or Bitcoin reorganization must not create a second accepted state or reuse signing material.

## Adversaries

The protocol considers an adversary that may corrupt any number of past or future Holders and at most `t - 1` of the `n` committee members. The paper uses a static-corruption model. A deployment must not silently claim protection against stronger adaptive corruption without a separate analysis.

The implementation also assumes hostile network clients, malformed proofs, replayed events, equivocation attempts, compromised control credentials, unavailable peers, disk faults, process crashes, and a Bitcoin chain reorganization.

An attacker may:

- submit malformed, oversized, duplicate, stale, or out-of-order messages
- publish inconsistent invoice material or an unusable transfer credential
- replay an entry across channels, steps, networks, or protocol versions
- compromise a minority of committee nodes
- delay, censor, or reorder messages at the transport layer
- crash a daemon between signing, persistence, and response
- steal an unencrypted database or backup
- try to make two daemon instances use the same identity
- compromise a build or release pipeline

## Trust assumptions

Committee threshold
: At most `t - 1` committee members are corrupted. At least `t` honest members remain responsive for liveness. Each member runs an independent process and protects its own share.

Thunderbolt Ledger
: For each channel, the Ledger provides append-only persistence, a single committed order, and eventual inclusion and retrieval of valid entries. A simple single-process reference Ledger is suitable for development only unless the operator accepts its weaker trust model.

Cryptography
: The proofs rely on elliptic-curve discrete-log hardness, the Paillier Decisional Composite Residuosity assumption, and Fiat-Shamir in the random-oracle model. The implementation also depends on a correct CSPRNG, domain separation, canonical encoding, constant-time secret handling where required, and safe dependency versions.

Bitcoin Chain
: Operators use a validated Bitcoin backend and a confirmation policy suitable for the selected network. Reorganizations and replacement transactions are expected events, not exceptional assumptions.

Host and operator
: The operating system, process isolation, file permissions, clock, entropy source, backup handling, and release verification are part of the trusted computing base.

## Required defenses

- Bind every proof and signature to protocol version, Bitcoin network, channel, step, invoice, and prior event.
- Authenticate protocol entries independently of TLS.
- Use strict parsing, canonical encoding, size limits, deadlines, bounded queues, and proof-verification concurrency limits.
- Make every mutation idempotent and return the committed sequence and event hash.
- Persist events, secret updates, and outbound work atomically.
- Encrypt secrets and backups at rest and keep keys outside ordinary configuration files.
- Persist signing sessions before emitting partial signatures and permanently consume nonce material.
- Reject simultaneous use of one identity database.
- Track Bitcoin confirmations and roll state back only through an explicit reorganization procedure.
- Redact secrets, credentials, raw proofs where sensitive, and personal data from logs and metrics.
- Sign release artifacts and publish checksums and a software bill of materials.

## Known limits and exclusions

- Mainnet is disabled in `v1.0.0-rc.1`.
- The runnable server is a single reference Ledger. It does not implement the paper's Byzantine Ledger fault model.
- The node library can inject trusted Invoice and Transfer verification into its atomic append path. The shipped daemon does not configure that verifier. It has no production Open, actor-signature, Bitcoin, quorum-receipt, or committee service path, and its optional regtest demo mode inserts synthetic verification attestations.
- Control uses bearer-authenticated loopback HTTP. The reserved Unix socket, remote control, and metrics are not implemented.
- Manual SQLite backups are verified but not encrypted by the daemon.
- The RC wire codec fixes Paillier values at 2048 bits, while the accepted paper evaluates 3072-bit Paillier.
- Stable version 2 channel bindings exist, but the active message and Ledger contract remains version 1 and has no actor-signed proposal envelope.
- The reducer allows one pending Invoice rather than the pending-Invoice set used by the paper's ideal state.
- Committee rollback protection depends on an independently authenticated monotonic revision floor. Generic committee restore is forbidden.
- Open has no reviewed DKG or provisioning ceremony that establishes the distributed committee state and its relationship to `P`.
- Finalize has no concrete `R_own` proof or audited combined-key Holder plus FROST implementation under `P`.
- Finalize is committee-dependent in the base protocol.
- The unilateral-exit overlay described in the paper is not implemented.
- Off-chain splitting is not implemented. A transfer moves ownership of the whole locked UTXO.
- The protocol does not route Lightning payments and does not speak the BOLT wire protocols.
- The base design does not promise unlinkability. Ledger observers can see channel activity and timing.
- Availability fails if fewer than `t` committee members can respond or if the Ledger fails its inclusion and retrieval guarantees.
- A threshold breach can authorize theft. Threshold cryptography distributes trust but does not remove it.
- Endpoint compromise can expose the current Holder secret before the protocol has a chance to protect it.
- The paper's proofs do not establish correctness of storage, transport, Bitcoin integration, deployment automation, or operator procedures.

## Abuse cases that must be tested

1. Reuse an invoice identifier in one channel and across two channels.
2. Replay a valid transfer on a different network or protocol version.
3. Submit two transfers against the same Holder state.
4. Start Finalize while a transfer waits for committee acknowledgements.
5. Deliver valid entries in different orders to different nodes.
6. Crash after a database commit but before the response, then retry the request.
7. Crash after creating threshold nonce material and before producing a partial signature.
8. Corrupt or omit one committee refresh share.
9. Stall enough committee members to fall below threshold.
10. Reorganize the funding or finalization transaction.
11. Restore an old backup over newer channel state.
12. Send a proof or event at every configured size and concurrency boundary.

Changes to the trust assumptions, proof bindings, event order, signing flow, or recovery rules require an update to this document in the same pull request.
