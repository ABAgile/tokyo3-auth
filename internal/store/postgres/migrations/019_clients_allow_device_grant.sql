-- allow_device_grant opts an OAuth client into the RFC 8628 device
-- authorization grant flow. POST /device_authorization rejects clients
-- without this flag with unauthorized_client. Defaults to FALSE so
-- adding the column doesn't silently broaden any existing client's
-- attack surface; ops flips it on for the auth-aws-creds CLI client
-- (and any future headless client that needs it).
ALTER TABLE clients ADD COLUMN allow_device_grant BOOLEAN NOT NULL DEFAULT FALSE;
