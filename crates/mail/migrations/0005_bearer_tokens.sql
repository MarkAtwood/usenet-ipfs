-- SQLite dialect. PG equivalents: token_hash BYTEA, created_at/expires_at BIGINT.
CREATE TABLE IF NOT EXISTS bearer_tokens (
    id TEXT PRIMARY KEY NOT NULL,
    token_hash BLOB NOT NULL UNIQUE,
    username TEXT NOT NULL,
    label TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);
