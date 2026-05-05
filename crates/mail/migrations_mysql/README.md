# Mail MySQL/MariaDB Migration Skeleton

This directory contains MySQL/MariaDB-compatible migrations for stoa-mail.
These are a skeleton — `src/migrations.rs` does not yet activate the MySQL
path; implement it by adding a `mysql://` branch to `run_migrations()`.

## Status

Skeleton only. sqlx supports MySQL natively via `AnyPool` (`mysql` feature),
so activation is low-effort once a concrete requirement exists.

## Key dialect differences from PostgreSQL canonical

| Construct | PostgreSQL | MySQL/MariaDB |
|---|---|---|
| Auto-increment PK | `BIGSERIAL PRIMARY KEY` | `BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY` |
| Binary data | `BYTEA` | `MEDIUMBLOB` (up to 16MB) or `LONGBLOB` |
| Boolean | `INTEGER` | `TINYINT(1)` |
| `ON CONFLICT DO NOTHING` | native | `INSERT IGNORE INTO …` |
| `RETURNING` clause | supported (PG 9.5+) | not supported (MariaDB 10.5+ has limited support) |
| Text primary key length | unlimited | requires explicit length for TEXT PKs: `VARCHAR(767)` or `TEXT(767)` |
| `IF NOT EXISTS` on INDEX | supported | supported (MySQL 8.0.1+; not in older MariaDB) |

## Activation

1. Add `mysql` to sqlx features in `Cargo.toml`.
2. Add a `mysql://` branch in `src/migrations.rs::run_migrations()`.
3. Run `cargo test -p stoa-integration-tests --test postgres_migrations` with
   `STOA_TEST_MYSQL_URL` set to verify.

## Target use cases

- AWS RDS for MySQL
- Azure Database for MySQL
- On-premise MariaDB
