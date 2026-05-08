-- SQLite has no `ADD COLUMN IF NOT EXISTS`; the schema_migrations tracking
-- table guarantees this runs only once per database.
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
