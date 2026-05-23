-- AWS OIDC federation: role catalog + assignments + revocation bookkeeping.
-- SQLite mirror of postgres 013 — see that file for the design notes.

CREATE TABLE aws_accounts (
    id                   TEXT     PRIMARY KEY,
    account_id           TEXT     NOT NULL UNIQUE,
    alias                TEXT     NOT NULL DEFAULT '',
    oidc_provider_arn    TEXT     NOT NULL,
    created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE aws_roles (
    id                       TEXT     PRIMARY KEY,
    account_id               TEXT     NOT NULL REFERENCES aws_accounts(id) ON DELETE CASCADE,
    role_arn                 TEXT     NOT NULL UNIQUE,
    audience                 TEXT     NOT NULL,
    display_name             TEXT     NOT NULL,
    require_step_up_mfa      INTEGER  NOT NULL DEFAULT 0,
    max_session_duration_sec INTEGER  NOT NULL DEFAULT 3600,
    created_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at               DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX aws_roles_account_idx ON aws_roles(account_id);

CREATE TABLE aws_role_assignments (
    id           TEXT     PRIMARY KEY,
    group_id     TEXT     NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    role_id      TEXT     NOT NULL REFERENCES aws_roles(id)   ON DELETE CASCADE,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (group_id, role_id)
);

CREATE INDEX aws_role_assignments_role_idx  ON aws_role_assignments(role_id);
CREATE INDEX aws_role_assignments_group_idx ON aws_role_assignments(group_id);

CREATE TABLE aws_revoked_users (
    role_id     TEXT     NOT NULL REFERENCES aws_roles(id) ON DELETE CASCADE,
    sub_uuid    TEXT     NOT NULL,
    revoked_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, sub_uuid)
);

CREATE INDEX aws_revoked_users_revoked_at_idx ON aws_revoked_users(revoked_at);
