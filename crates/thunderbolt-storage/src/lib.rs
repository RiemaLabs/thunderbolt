//! Durable SQLite persistence for Bitcoin Thunderbolt nodes.
//!
//! [`SqliteStorage`] stores protocol ledger entries and their resulting channel
//! snapshots in one transaction. [`SqliteStorage::append_verified_proposal`]
//! additionally keeps proposal deduplication, trusted verification, evidence,
//! reduction, and persistence under the same writer lock. A successful append
//! is therefore visible in full after a restart, while a failed append leaves
//! no partial entry, evidence, snapshot, or request mapping behind.

mod error;
mod migrations;
mod store;

pub use error::{Result, StorageError, VerifiedAppendError, VerifiedRequestConflict};
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use store::{
    AppendOutcome, IntegrityReport, ProposalDigest, SqliteStorage, StorageOptions, VerifiedAppendOutcome,
    VerifiedProposalContext, DEFAULT_PAGE_LIMIT, MAX_PAGE_BYTES, MAX_PAGE_LIMIT,
};
