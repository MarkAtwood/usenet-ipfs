CREATE TABLE IF NOT EXISTS subscriptions (
    user_id       BIGINT NOT NULL,
    group_name    VARCHAR(767) NOT NULL,
    subscribed_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, group_name),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
