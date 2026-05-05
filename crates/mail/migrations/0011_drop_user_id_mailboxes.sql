-- Migration 0011: replace user_mailboxes (user-partitioned) with mailboxes (shared).
-- SQLite dialect: uses CREATE/INSERT/DROP/RENAME because SQLite <3.35 does not
-- support DROP COLUMN. PG equivalent uses direct DDL (see migrations_pg/).
-- Old rows from user_mailboxes are intentionally NOT copied: their
-- mailbox_id values were computed as SHA-256(user_id || role), but new
-- code computes mailbox_id = SHA-256(role).  Copying stale IDs would
-- cause provision_mailboxes (INSERT OR IGNORE) to silently keep the old
-- IDs, breaking JMAP id lookups on upgraded deployments.
-- provision_mailboxes() at server startup repopulates the table.
CREATE TABLE mailboxes_new (
    mailbox_id TEXT    PRIMARY KEY,
    role       TEXT    NOT NULL UNIQUE,
    name       TEXT    NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 10
);
DROP TABLE user_mailboxes;
ALTER TABLE mailboxes_new RENAME TO mailboxes;
