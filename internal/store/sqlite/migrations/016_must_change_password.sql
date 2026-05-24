-- See postgres/016 for design notes. SQLite uses INTEGER for booleans.
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
