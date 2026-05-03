pub mod append;
pub mod backfill;
pub mod mem_storage;
pub mod reconcile;
pub mod sqlite_storage;
pub mod storage;
#[cfg(test)]
pub mod storage_tests;
pub mod types;
pub mod verify;

pub use backfill::{backfill, BackfillError};
pub use mem_storage::MemLogStorage;
pub use reconcile::{reconcile, ReconcileResult};
pub use sqlite_storage::SqliteLogStorage;
pub use storage::LogStorage;
pub use types::{LogEntry, LogEntryId, LogHead};
pub use verify::{tip_hash, verify_entry, verify_signature, VerifiedEntry, VerifyError};
