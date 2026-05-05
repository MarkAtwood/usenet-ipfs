-- Migration 0013 (SQLite): add user_id to state_version and jmap_change_log.
-- SQLite dialect: uses CREATE/INSERT/DROP/RENAME to add user_id and change PRIMARY KEY.
-- PG equivalent uses ALTER TABLE ADD COLUMN + DROP CONSTRAINT + ADD PRIMARY KEY
-- (see migrations_pg/0013_user_scope_state.sql).
--
-- Existing rows (all owned by user_id=1 in single-user v1) are preserved.
-- ON CONFLICT constraints are updated to include user_id so that per-user
-- state counters are fully isolated.

CREATE TABLE state_version_new (
    user_id INTEGER NOT NULL DEFAULT 1,
    scope   TEXT    NOT NULL,
    version INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, scope)
);
INSERT INTO state_version_new (user_id, scope, version)
    SELECT 1, scope, version FROM state_version;
DROP TABLE state_version;
ALTER TABLE state_version_new RENAME TO state_version;

CREATE TABLE jmap_change_log_new (
    user_id INTEGER NOT NULL DEFAULT 1,
    seq     INTEGER NOT NULL,
    scope   TEXT    NOT NULL,
    item_id TEXT    NOT NULL,
    change  TEXT    NOT NULL,
    PRIMARY KEY (user_id, seq, scope, item_id)
);
INSERT INTO jmap_change_log_new (user_id, seq, scope, item_id, change)
    SELECT 1, seq, scope, item_id, change FROM jmap_change_log;
DROP TABLE jmap_change_log;
ALTER TABLE jmap_change_log_new RENAME TO jmap_change_log;
