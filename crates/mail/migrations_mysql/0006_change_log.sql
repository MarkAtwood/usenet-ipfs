-- JMAP change log for incremental sync (/changes methods).
CREATE TABLE IF NOT EXISTS jmap_change_log (
    seq     BIGINT NOT NULL,
    scope   VARCHAR(64) NOT NULL,
    item_id VARCHAR(767) NOT NULL,
    change  VARCHAR(16) NOT NULL,
    PRIMARY KEY (seq, scope, item_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
