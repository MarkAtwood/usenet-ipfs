-- Add node_id to hlc_checkpoint so the originating node identity is
-- persisted alongside the timestamp.  Fixes the case where the
-- transit_instance_id table is unavailable on restart, which would
-- otherwise produce a new random node_id and potentially reuse timestamps
-- from a different node.
--
-- Existing row (if any) gets all-zero bytes as the default; the background
-- save task will overwrite with the real node_id on the next 30-second tick.
ALTER TABLE hlc_checkpoint ADD COLUMN node_id BYTEA NOT NULL DEFAULT '\x0000000000000000';
