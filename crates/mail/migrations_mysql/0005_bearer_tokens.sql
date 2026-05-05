-- MySQL/MariaDB dialect. MEDIUMBLOB replaces BYTEA for token_hash.
CREATE TABLE IF NOT EXISTS bearer_tokens (
    id         VARCHAR(255) NOT NULL PRIMARY KEY,
    token_hash MEDIUMBLOB NOT NULL,
    username   VARCHAR(255) NOT NULL,
    label      TEXT,
    created_at BIGINT NOT NULL,
    expires_at BIGINT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
-- Note: UNIQUE on MEDIUMBLOB requires explicit prefix length.
-- Enforce uniqueness at application level or use a hash column.
