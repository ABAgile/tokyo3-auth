-- Application portal: render OAuth2 clients as launchable tiles at
-- /portal/apps alongside AWS federation roles. The new columns gate
-- visibility (`show_in_portal`), describe how to launch the app
-- (`launch_url`), and offer two cosmetic hooks (`brand_color`,
-- `icon_url`). Visibility scoping reuses the aws_role_assignments
-- pattern: client_visibility links a client to one or more SCIM groups,
-- and a per-client `visible_to_all` shortcut covers org-wide tools
-- (status page, internal wiki) without a row per group.
--
-- Defaults are deliberate: existing rows (the portal sentinel client,
-- vault, github-compat, …) become invisible to /portal/apps unless an
-- operator explicitly opts them in. The portal page therefore stays
-- empty by default; admins curate the catalogue via the OAuth Client
-- edit form's new "Portal visibility" section.

ALTER TABLE clients ADD COLUMN show_in_portal  BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN launch_url      TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN brand_color     TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN icon_url        TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN visible_to_all  BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE client_visibility (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id  UUID        NOT NULL REFERENCES clients(id)     ON DELETE CASCADE,
    group_id   UUID        NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (client_id, group_id)
);

CREATE INDEX client_visibility_client_idx ON client_visibility(client_id);
CREATE INDEX client_visibility_group_idx  ON client_visibility(group_id);
