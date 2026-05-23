-- See postgres/014 for the design notes. SQLite supports RENAME COLUMN
-- natively since 3.25 (modernc.org/sqlite ships a recent build).
ALTER TABLE aws_roles RENAME COLUMN audience TO slug;
