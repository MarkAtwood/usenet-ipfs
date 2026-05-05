-- Migration 0012 (MySQL): replace mailbox_messages with messages (shared).
-- No FK on mailbox_id (same reason as PG/SQLite variants).
CREATE TABLE messages (
    id            BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    mailbox_id    VARCHAR(255) NOT NULL,
    envelope_from VARCHAR(767) NOT NULL,
    envelope_to   VARCHAR(767) NOT NULL,
    raw_message   MEDIUMBLOB NOT NULL,
    received_at   VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%dT%H:%i:%SZ'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_messages_mailbox ON messages (mailbox_id);
INSERT INTO messages (id, mailbox_id, envelope_from, envelope_to, raw_message, received_at)
    SELECT id, mailbox_id, envelope_from, envelope_to, raw_message, received_at
    FROM   mailbox_messages;
DROP TABLE mailbox_messages;
