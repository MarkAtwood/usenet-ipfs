-- Migration 0014 created mta_sts_cache for a planned MySQL-backed
-- MTA-STS policy cache.  The cache was never implemented; MtaStsEnforcer
-- (stoa-smtp) uses an in-memory HashMap instead.  Drop the unused table.
DROP TABLE IF EXISTS mta_sts_cache;
