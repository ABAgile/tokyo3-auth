-- See postgres/migrations/011_client_backchannel_logout_uri.sql for rationale.
ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT;
