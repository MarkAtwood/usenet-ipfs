-- SQLite dialect. PG equivalents:
--   id BIGSERIAL PRIMARY KEY
--   user_id BIGINT
--   raw_message BYTEA
--   received_at DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
CREATE TABLE IF NOT EXISTS mailbox_messages (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    mailbox_id    TEXT    NOT NULL,
    envelope_from TEXT    NOT NULL,
    envelope_to   TEXT    NOT NULL,
    raw_message   BLOB    NOT NULL,
    received_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_mailbox_messages_user_mailbox
    ON mailbox_messages (user_id, mailbox_id);
