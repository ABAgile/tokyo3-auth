-- Split the session expiry into access + refresh windows so the OAuth/OIDC
-- contract advertised in /token responses ("expires_in") actually matches what
-- bearerAuth enforces. The old `expires_at` column doubled as both — the
-- response said 1h but the row sat for 24h.
--
-- After this migration:
--   access_expires_at  — when the bearer access token stops being honoured
--   refresh_expires_at — when the refresh token grant stops working (was: expires_at)
--
-- Existing rows: access_expires_at is seeded from the old expires_at so they
-- continue working until their natural refresh-window end. Callers that haven't
-- been deployed yet keep emitting just `expires_at`-equivalent semantics.

ALTER TABLE sessions RENAME COLUMN expires_at TO refresh_expires_at;
ALTER TABLE sessions ADD COLUMN access_expires_at TIMESTAMPTZ;
UPDATE sessions SET access_expires_at = refresh_expires_at WHERE access_expires_at IS NULL;
ALTER TABLE sessions ALTER COLUMN access_expires_at SET NOT NULL;

ALTER INDEX sessions_expires_idx RENAME TO sessions_refresh_expires_idx;
CREATE INDEX IF NOT EXISTS sessions_access_expires_idx ON sessions(access_expires_at);
