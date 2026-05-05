-- MySQL/MariaDB dialect. Uses DATETIME instead of TIMESTAMPTZ.
-- The table is dropped in 0015 so this is a no-op in practice.
CREATE TABLE IF NOT EXISTS mta_sts_cache (
    domain       VARCHAR(255) NOT NULL PRIMARY KEY,
    policy_id    VARCHAR(255) NOT NULL,
    mode         VARCHAR(32) NOT NULL,
    mx_patterns  TEXT NOT NULL,
    max_age_secs INT NOT NULL,
    fetched_at   DATETIME NOT NULL,
    expires_at   DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
