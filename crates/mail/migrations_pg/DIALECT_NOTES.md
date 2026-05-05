# Mail Migration Dialect Notes (PostgreSQL canonical)

This directory contains PostgreSQL-canonical migrations.  
See `migrations/DIALECT_NOTES.md` for the full dialect comparison table.

## PostgreSQL is the production backend

These migrations are run when `stoa_mail::migrations::run_migrations()` is
called with a `postgres://` URL.

## Key constructs used here (not in SQLite)

- `BIGSERIAL PRIMARY KEY` — auto-increment 64-bit integer primary key
- `BIGINT` — 64-bit integer columns (IDs, Unix timestamps)
- `BYTEA` — binary data (article CIDs, token hashes, raw messages)
- `TIMESTAMPTZ` — timezone-aware timestamp (mta_sts_cache; table dropped in 0015)
- `ALTER TABLE … ADD COLUMN / DROP CONSTRAINT / ADD PRIMARY KEY` — used in 0013
  instead of the CREATE/INSERT/DROP/RENAME pattern required by SQLite <3.35
- `to_char(now() AT TIME ZONE 'UTC', '...')` — current timestamp as TEXT
