-- MySQL/MariaDB dialect. MEDIUMBLOB replaces BYTEA for article_cid.
CREATE TABLE IF NOT EXISTS user_flags (
    user_id     BIGINT NOT NULL,
    article_cid MEDIUMBLOB NOT NULL,
    seen        TINYINT(1) NOT NULL DEFAULT 0,
    flagged     TINYINT(1) NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, article_cid(64)),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
