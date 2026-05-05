CREATE TABLE IF NOT EXISTS activitypub_followers (
    group_name  VARCHAR(255) NOT NULL,
    actor_url   VARCHAR(767) NOT NULL,
    inbox_url   TEXT NOT NULL,
    followed_at BIGINT NOT NULL,
    PRIMARY KEY (group_name, actor_url)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
