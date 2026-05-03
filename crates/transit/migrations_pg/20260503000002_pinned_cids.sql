-- Pin table: tracks which CIDs are explicitly operator-pinned.
--
-- The GC candidate query uses NOT IN (SELECT cid FROM pinned_cids) to
-- exclude pinned articles from GC consideration.  This table is created
-- here rather than at query time so CREATE TABLE is never executed on
-- the hot GC path.
CREATE TABLE IF NOT EXISTS pinned_cids (
    cid          TEXT    PRIMARY KEY NOT NULL,
    pinned_at_ms BIGINT  NOT NULL
);
