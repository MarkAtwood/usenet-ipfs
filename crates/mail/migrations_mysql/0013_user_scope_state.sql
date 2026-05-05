-- Migration 0013 (MySQL): add user_id to state_version and jmap_change_log.
-- MySQL supports ALTER TABLE ADD COLUMN similar to PostgreSQL.
-- Note: MySQL does not support DROP PRIMARY KEY and ADD PRIMARY KEY in one
-- statement on tables with AUTO_INCREMENT; use two separate ALTER statements.
ALTER TABLE state_version ADD COLUMN user_id BIGINT NOT NULL DEFAULT 1 FIRST;
ALTER TABLE state_version DROP PRIMARY KEY, ADD PRIMARY KEY (user_id, scope);

ALTER TABLE jmap_change_log ADD COLUMN user_id BIGINT NOT NULL DEFAULT 1 FIRST;
ALTER TABLE jmap_change_log DROP PRIMARY KEY, ADD PRIMARY KEY (user_id, seq, scope, item_id);
