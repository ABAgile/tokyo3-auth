-- See postgres/015 for design notes. SQLite mirror.

ALTER TABLE clients ADD COLUMN show_in_portal  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN launch_url      TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN brand_color     TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN icon_url        TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN visible_to_all  INTEGER NOT NULL DEFAULT 0;

CREATE TABLE client_visibility (
    id         TEXT     PRIMARY KEY,
    client_id  TEXT     NOT NULL REFERENCES clients(id)     ON DELETE CASCADE,
    group_id   TEXT     NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (client_id, group_id)
);

CREATE INDEX client_visibility_client_idx ON client_visibility(client_id);
CREATE INDEX client_visibility_group_idx  ON client_visibility(group_id);
