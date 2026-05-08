-- Insert the built-in portal sentinel client used for portal sessions.
-- The well-known UUID avoids a FK violation when portal sessions are created
-- without going through the OAuth2 authorization flow.
INSERT INTO clients (id, client_id, client_secret_hash, name, redirect_uris, scopes, public)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'portal',
    '',
    'tokyo3-auth Portal',
    '[]',
    '["portal","admin"]',
    1
)
ON CONFLICT (id) DO NOTHING;
