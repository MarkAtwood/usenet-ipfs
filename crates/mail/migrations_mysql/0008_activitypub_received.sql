-- Deduplication table for received ActivityPub activities.
CREATE TABLE IF NOT EXISTS activitypub_received (
    activity_id VARCHAR(767) NOT NULL PRIMARY KEY,
    received_at BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
