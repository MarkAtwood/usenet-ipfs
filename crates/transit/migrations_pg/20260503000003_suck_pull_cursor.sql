-- suck_pull cursor: tracks the last-fetched timestamp per group for
-- incremental NNTP suck/pull operations.  Created here rather than at
-- function-call time so CREATE TABLE is never executed on the suck_pull
-- hot path.
CREATE TABLE IF NOT EXISTS suck_pull_cursor (
    group_name          TEXT    PRIMARY KEY NOT NULL,
    last_fetched_unix   BIGINT  NOT NULL
);
