-- Migration 0012: replace mailbox_messages (user-partitioned) with messages (shared).
-- SQLite dialect: uses CREATE/INSERT/DROP/RENAME because SQLite <3.35 does not
-- support DROP COLUMN. PG equivalent uses direct DDL (see migrations_pg/).
-- No FK on mailbox_id: migration 0011 discards old mailbox rows (mailbox_id scheme
-- changed from SHA-256(user_id||role) to SHA-256(role)), so existing mailbox_messages
-- rows cannot satisfy the FK. Messages are orphaned but retained; provision_mailboxes()
-- repopulates mailboxes at startup with new IDs.
CREATE TABLE messages_new (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mailbox_id    TEXT    NOT NULL,
    envelope_from TEXT    NOT NULL,
    envelope_to   TEXT    NOT NULL,
    raw_message   BLOB    NOT NULL,
    received_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_messages_mailbox ON messages_new (mailbox_id);
INSERT INTO messages_new (id, mailbox_id, envelope_from, envelope_to, raw_message, received_at)
    SELECT id, mailbox_id, envelope_from, envelope_to, raw_message, received_at
    FROM   mailbox_messages;
DROP TABLE mailbox_messages;
ALTER TABLE messages_new RENAME TO messages;
