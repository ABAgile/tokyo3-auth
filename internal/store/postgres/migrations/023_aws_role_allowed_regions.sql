-- Per-role narrowing of the portal's AWS console regions. Comma-separated
-- region names; '' = inherit the server-wide list (AUTHD_AWS_REGIONS).
ALTER TABLE aws_roles ADD COLUMN allowed_regions TEXT NOT NULL DEFAULT '';
