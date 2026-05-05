CREATE TABLE IF NOT EXISTS user_mailboxes (
    user_id    BIGINT NOT NULL,
    role       VARCHAR(64) NOT NULL,
    mailbox_id VARCHAR(255) NOT NULL,
    name       VARCHAR(255) NOT NULL,
    sort_order BIGINT NOT NULL DEFAULT 10,
    PRIMARY KEY (user_id, role),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY uq_user_mailbox_id (user_id, mailbox_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
