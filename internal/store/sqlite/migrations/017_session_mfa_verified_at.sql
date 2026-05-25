-- See postgres/017 for design notes. SQLite stores timestamps as TEXT
-- in ISO-8601 (matches the rest of the schema's TIMESTAMP columns).
ALTER TABLE sessions ADD COLUMN mfa_verified_at TIMESTAMP NULL;
UPDATE sessions SET mfa_verified_at = created_at WHERE mfa_verified = 1;
