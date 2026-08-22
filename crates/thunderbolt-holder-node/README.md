# Bitcoin Thunderbolt Holder node

`thunderbolt-holder-node` is the long-running Holder/Recipient role service.
It combines the private `thunderbolt-holder` engine and fenced encrypted
keystore with a durable SQLite outbox and a trait-based signed-v2 Ledger
adapter.

The crate opens no TCP listener and implements no remote administration.
Applications should expose its local-control types only over an owner-only
Unix socket, named pipe, or equivalent local IPC boundary.

The service does not infer consensus finality from `ExecutedBlockV2`. Its
Ledger client returns untrusted candidates to a separate `FinalityVerifier`,
which must validate quorum/header finality, the exact chain, inclusion, entry,
and channel predecessor before issuing a typed `TrustedLedgerReceipt`. The
service never constructs a `DurableAcknowledgement`; it only consumes one
supplied by that trusted receipt.

Every local command is durably inserted into a bounded SQLite outbox before it
can be submitted. SQLite runs in WAL mode with `synchronous=FULL`; a process
lock excludes a second role instance. Request digests and caller command IDs
are independently deduplicated, retries reuse the originally stored signed
proposal, and channel-scoped finalized cursors advance atomically with outbox
completion. A dirty lifecycle marker detects crash recovery.

The committed Holder engine still implements the v1 proof-envelope domain.
Those envelopes and its compressed-key identity are not byte-wrapped into v2
events. A reviewed v2 Holder proof/identity bridge remains a release gate.

Mainnet and Testnet4 are rejected. Bitcoin settlement and threshold signing
are capability traits whose bundled implementations fail closed. They must be
replaced with audited implementations before those actions are enabled.
