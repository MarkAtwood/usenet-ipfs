-- SQLite dialect. PG equivalents: user_id BIGINT, article_cid BYTEA.
CREATE TABLE IF NOT EXISTS user_flags (
    user_id INTEGER NOT NULL,
    article_cid BLOB NOT NULL,
    seen INTEGER NOT NULL DEFAULT 0,
    flagged INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, article_cid),
    FOREIGN KEY (user_id) REFERENCES users(id)
);
