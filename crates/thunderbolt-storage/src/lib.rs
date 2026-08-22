//! Durable SQLite persistence for Bitcoin Thunderbolt nodes.
//!
//! [`SqliteStorage`] stores protocol ledger entries and their resulting channel
//! snapshots in one transaction. A successful append is therefore visible in
//! full after a restart, while a failed append leaves neither half behind.

mod error;
mod migrations;
mod store;

pub use error::{Result, StorageError};
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use store::{
    AppendOutcome, IntegrityReport, SqliteStorage, StorageOptions, DEFAULT_PAGE_LIMIT, MAX_PAGE_BYTES, MAX_PAGE_LIMIT,
};
