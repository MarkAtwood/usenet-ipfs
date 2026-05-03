use std::future::Future;

use cid::Cid;

use crate::article::GroupName;
use crate::error::StorageError;
use crate::group_log::types::{LogEntry, LogEntryId};

/// Async storage backend for the per-group Merkle-CRDT log.
///
/// All futures returned by this trait are `Send` so implementations can be
/// shared across tokio tasks without wrapping in a mutex.
pub trait LogStorage: Send + Sync {
    /// Persist a log entry. Returns `StorageError::DuplicateEntry` if an entry
    /// with the same id already exists.
    fn insert_entry(
        &self,
        id: LogEntryId,
        entry: LogEntry,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Retrieve a log entry by id. Returns `None` if not found.
    fn get_entry(
        &self,
        id: &LogEntryId,
    ) -> impl Future<Output = Result<Option<LogEntry>, StorageError>> + Send;

    /// Return `true` if an entry with the given id exists.
    fn has_entry(&self, id: &LogEntryId)
        -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Return only the parent CIDs of an entry, or `None` if not found.
    ///
    /// More efficient than `get_entry` when the caller only needs to traverse
    /// the DAG (e.g. reconcile BFS), because it skips deserializing the full
    /// log entry.
    fn get_parent_cids(
        &self,
        id: &LogEntryId,
    ) -> impl Future<Output = Result<Option<Vec<Cid>>, StorageError>> + Send;

    /// Return the current tip ids for a group (empty vec if no tips set).
    fn list_tips(
        &self,
        group: &GroupName,
    ) -> impl Future<Output = Result<Vec<LogEntryId>, StorageError>> + Send;

    /// Replace the tip set for a group atomically.
    fn set_tips(
        &self,
        group: &GroupName,
        tips: &[LogEntryId],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Atomically advance the tip set: remove `parents_to_remove` and add
    /// `new_tip`.
    ///
    /// This is the CRDT-correct way to update tips after an append.  Two
    /// concurrent appends that each remove the same parent will both survive
    /// as concurrent tips rather than one overwriting the other.
    ///
    /// If `new_tip` is already in the tip set the insert is idempotent.
    /// If a parent is not in the tip set its removal is a no-op.
    fn advance_tips(
        &self,
        group: &GroupName,
        parents_to_remove: &[LogEntryId],
        new_tip: &LogEntryId,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Atomically insert an entry and advance the tip set in a single
    /// operation.  This prevents the crash window between `insert_entry` and
    /// `advance_tips` that would leave an orphaned log entry with no tip.
    ///
    /// Returns `StorageError::DuplicateEntry` if the entry already exists;
    /// in that case the tip set is **not** modified.
    ///
    /// There is no default implementation.  Each backend must implement this
    /// method.  Persistent backends (e.g. SQLite) must wrap both operations in
    /// a single transaction.  In-memory backends may call the two operations
    /// sequentially — there is no durable state to corrupt on a crash.
    fn insert_entry_and_advance_tips(
        &self,
        id: LogEntryId,
        entry: LogEntry,
        group: &GroupName,
        parents_to_remove: &[LogEntryId],
        new_tip: &LogEntryId,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Returns the number of DAG tip entries for the group, not total log
    /// entries. For a group with 1 000 entries branched into 2 concurrent tips
    /// this returns 2, not 1 000.
    fn tip_count(
        &self,
        group: &GroupName,
    ) -> impl Future<Output = Result<u64, StorageError>> + Send;
}
