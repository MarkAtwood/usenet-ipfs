-- Migration 0011 (MySQL): replace user_mailboxes with mailboxes (shared).
-- MySQL supports RENAME TABLE and DROP TABLE directly.
-- Old rows are intentionally NOT copied (same reason as PG/SQLite variants).
CREATE TABLE mailboxes (
    mailbox_id VARCHAR(255) NOT NULL PRIMARY KEY,
    role       VARCHAR(64) NOT NULL UNIQUE,
    name       VARCHAR(255) NOT NULL,
    sort_order BIGINT NOT NULL DEFAULT 10
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
DROP TABLE user_mailboxes;
