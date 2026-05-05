# Mail Migration Dialect Notes

This directory contains SQLite-dialect migrations. A parallel `migrations_pg/`
directory contains the PostgreSQL-canonical form. A `migrations_mysql/` directory
contains a MySQL/MariaDB skeleton.

## Canonical backend

**PostgreSQL is the production/staging canonical backend.**  
**SQLite is supported for local development and testing only.**

The `stoa_mail::migrations::run_migrations()` function selects the correct
migration directory automatically based on the URL prefix:
- `sqlite://` → this directory (`migrations/`)
- `postgres://` / `postgresql://` → `migrations_pg/`

## Dialect differences

| Construct | SQLite form | PostgreSQL form | Notes |
|---|---|---|---|
| Auto-increment PK | `INTEGER PRIMARY KEY AUTOINCREMENT` | `BIGSERIAL PRIMARY KEY` | SQLite requires `INTEGER` (not `INT`) for ROWID alias |
| Integer columns (IDs, timestamps) | `INTEGER` | `BIGINT` | SQLite stores all integers as 8-byte regardless; PG distinguishes sizes |
| Binary/blob columns | `BLOB` | `BYTEA` | Used for `article_cid`, `token_hash`, `raw_message` |
| Current timestamp | `datetime('now')` or `strftime('%Y-%m-%dT%H:%M:%SZ','now')` | `to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')` | Both produce ISO 8601 strings stored in TEXT columns |
| Timestamp type | `TEXT` (ISO 8601 string) | `TIMESTAMPTZ` (native) or `TEXT` | `mta_sts_cache` uses TIMESTAMPTZ in PG; TEXT in SQLite |
| Upsert | `INSERT OR IGNORE` | `INSERT … ON CONFLICT DO NOTHING` | sqlx `AnyPool` translates `INSERT OR IGNORE` for SQLite but NOT for PG; PG migrations use explicit `ON CONFLICT` |
| ADD COLUMN to restructure | CREATE TABLE new / INSERT / DROP / RENAME | `ALTER TABLE … ADD COLUMN` | SQLite <3.35 does not support DROP COLUMN; uses the copy-rename pattern |
| Constraint name drop | N/A (SQLite has no named PK constraints) | `ALTER TABLE … DROP CONSTRAINT <name>` | Migration 0013 uses ADD/DROP PRIMARY KEY in PG |
| Boolean columns | `INTEGER` (0/1) | `INTEGER` (0/1) | Both dialects; BOOLEAN type available in PG but not used for max compat |

## AnyPool bind placeholder

Both SQLite and PostgreSQL support `?` as bind placeholder when using
`sqlx::AnyPool`. The PG-native `$1`, `$2`, … are NOT used in the migration SQL
or application queries — `AnyPool` handles translation transparently.

## SQLite approximation notes

The following constructs in SQLite migrations are approximations of their
PG counterparts. They are functionally equivalent for the v1 single-user
deployment model:

- **0011, 0012**: SQLite uses CREATE/INSERT/DROP/RENAME to restructure
  tables because SQLite <3.35 lacks `ALTER TABLE … DROP COLUMN`. PG uses
  direct DDL. The end-state schema is identical.

- **0013**: SQLite rebuilds `state_version` and `jmap_change_log` via
  CREATE/INSERT/DROP/RENAME to add `user_id` and change the PRIMARY KEY.
  PG uses `ALTER TABLE … ADD COLUMN` + `DROP CONSTRAINT` + `ADD PRIMARY KEY`.
  End-state is identical.

- **0014/0015 (mta_sts_cache)**: SQLite stores `fetched_at`/`expires_at` as
  TEXT; PG stores them as `TIMESTAMPTZ`. The table is dropped in 0015 so
  this difference is moot in practice.

## Adding a new migration

1. Write the PG-canonical form in `migrations_pg/NNNN_description.sql`.
2. Write the SQLite-compatible form in `migrations/NNNN_description.sql`.
3. If the schemas differ, document the difference in this file.
4. If a MySQL/MariaDB form is needed, add it to `migrations_mysql/` and
   update `migrations/DIALECT_NOTES.md`.
5. Update `src/migrations.rs` if MySQL support is being activated.
