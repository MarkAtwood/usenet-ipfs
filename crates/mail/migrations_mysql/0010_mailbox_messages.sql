-- MySQL/MariaDB dialect. MEDIUMBLOB replaces BYTEA for raw_message.
-- NOW() used for received_at default (TEXT storage).
CREATE TABLE IF NOT EXISTS mailbox_messages (
    id            BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT NOT NULL,
    mailbox_id    VARCHAR(255) NOT NULL,
    envelope_from VARCHAR(767) NOT NULL,
    envelope_to   VARCHAR(767) NOT NULL,
    raw_message   MEDIUMBLOB NOT NULL,
    received_at   VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%dT%H:%i:%SZ')),
    FOREIGN KEY (user_id) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_mailbox_messages_user_mailbox
    ON mailbox_messages (user_id, mailbox_id);
