-- See postgres/019 for design notes. SQLite uses INTEGER for booleans.
ALTER TABLE clients ADD COLUMN allow_device_grant INTEGER NOT NULL DEFAULT 0;
