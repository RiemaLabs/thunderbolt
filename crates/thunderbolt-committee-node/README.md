# Bitcoin Thunderbolt Committee Node

This crate is the restart-safe service boundary for one independently operated
Committee member. It combines the one-member cryptographic engine and encrypted
checkpoint-fenced keystore with a bounded SQLite inbox, acknowledgement outbox,
and finalized Ledger cursor.

It prepares bounded, whole-block, globally contiguous `ExecutedBlockV2` ranges
beginning at an exact durable height and predecessor application hash. Empty
blocks are explicit and pages never end mid-block. Before any external trust
transition, the authority-free canonical range is committed and read back from
the role database. Only the resulting private-constructor staged capability can
be finalized. A compact commitment, exact entry, and Merkle proof are retained
only for matched Invoice/Transfer pairs. Raw receipts and provider labels are
never serialized. The shipped Ledger and finality capabilities fail closed.

The Ledger does not commit a refresh ordinal or refresh index. The service
therefore derives its own processed-refresh count and last-Transfer hash only
while scanning every finalized block and every executed position in order. A
server-filtered refresh feed, locator response, or RPC continuation token is
never treated as a completeness proof. Unmatched, relevant Invoice evidence is
stored locally until a later contiguous Transfer consumes it or trusted block
time expires it.

The service stores bounded durable attestations only for retained pending
Invoices, compact matched pairs, and the last global cursor block, never an
expiring raw light-client receipt. Each retained attestation is reauthenticated
before it can authorize later scanning or private processing.
The verifier profile ID and crash-safe coordinator ID are immutable in node
configuration, SQLite identity, every staged range, and every durable
capability. A different client or verifier is rejected before it can verify or
mutate state.

Schema-v1/v2 databases with any legacy cursor, inbox, or outbox progress are
rejected before migration. Those rows may contain full blocks, v1 envelopes,
or raw receipts and require an offline verified migrator. Only an exact empty
legacy database may migrate atomically to schema v4. A schema-v3 database must
likewise have no cursor, pending Invoice, inbox, or outbox state.

Pending-Invoice changes, compact matched records, the locally derived refresh
chain, the whole-block global cursor, and deletion of the exact staged range
commit in one immediate SQLite transaction. Gaps, omitted empty blocks, forks,
backwards heads, oversized ranges, alternate exact replays, and conflicting
duplicate requests fail closed before the cursor changes.

Ledger preparation and finality are explicitly cancellable async boundaries. A
cancelled prepare or explicit no-range result leaves no stage. Once a range is
prepared, synchronous staging commits and reads it back before the mutable
finalizer is awaited. Cancellation, partial coordinator progress, or ambiguous
finalization leaves that stage intact and never advances the role cursor.
Startup inspection returns the exact recovery handoff; normal open rejects an
unacknowledged stage, and recovery open requires byte-for-byte equality with the
inspected handoff. After finalization, filtering and the one immediate
cursor/state/stage transaction contain no suspension point.

SQLite requires an absolute normalized path under an existing owner-only safe
ancestry. The node creates mode-0600 files, opens with no-follow semantics,
rejects symlinks and hardlinks, binds a random store ID plus canonical
path/device/inode digest, retains and rechecks the exact device/inode,
prevents a second in-process handle to the same file, and reads back
foreign-key, WAL, and FULL-synchronous settings. In-memory and URI databases
are not production modes. The last block's bounded durable finality capability
is stored with the cursor and externally reauthenticated before that cursor is
used for another scan.

The service reparses `PublicMessageV2` RecipientShare, ThresholdRefresh, and
Transfer artifacts only from authenticated signed event bytes. It exact-binds
their channel, invoice, step, roster, anchor, ciphertext, event, inclusion, and
finality fields, then requires the private runtime's non-mutating proof/roster
validation before cursor advance. A crash after a future v2
engine's encrypted share update but before SQLite acknowledgement commit is
recoverable by deterministic runtime replay.

The committed `CommitteeMemberEngine` still accepts legacy v1 transcripts, so
its adapter reports `V2RuntimeUnavailable` before fetching, persistence, cursor
advance, private mutation, or acknowledgement. A real share update waits on the
reviewed core-v2/Committee migration; v2 transcripts are never reinterpreted as
v1. The concrete async Ledger-Comet client is also an external deployment gate.

No Committee-authored v2 event currently exists, so acknowledgements remain
unsigned local outbox records. The shipped signer hook fails closed. The crate
does not implement or claim DKG, FROST signing or aggregation, CometBFT
finality, automatic reorg recovery, mainnet readiness, or Testnet4 support.
