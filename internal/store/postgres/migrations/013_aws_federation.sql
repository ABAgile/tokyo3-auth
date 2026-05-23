-- AWS OIDC federation: role catalog + assignments + revocation bookkeeping.
--
-- The federation flow itself is credential-less at auth's side; AWS verifies
-- the signed id_token via the public JWKS endpoint. These tables only exist so
-- the portal can render per-user role tiles, the federation handler can mint
-- audience-scoped tokens, and the revocation provisioner can update the
-- AuthRevokedUsers inline policy on each managed role when a user is
-- deactivated.

CREATE TABLE aws_accounts (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id           TEXT        NOT NULL UNIQUE,
    alias                TEXT        NOT NULL DEFAULT '',
    oidc_provider_arn    TEXT        NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE aws_roles (
    id                       UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id               UUID        NOT NULL REFERENCES aws_accounts(id) ON DELETE CASCADE,
    role_arn                 TEXT        NOT NULL UNIQUE,
    audience                 TEXT        NOT NULL,
    display_name             TEXT        NOT NULL,
    require_step_up_mfa      BOOLEAN     NOT NULL DEFAULT FALSE,
    max_session_duration_sec INTEGER     NOT NULL DEFAULT 3600,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX aws_roles_account_idx ON aws_roles(account_id);

CREATE TABLE aws_role_assignments (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id     UUID        NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
    role_id      UUID        NOT NULL REFERENCES aws_roles(id)   ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (group_id, role_id)
);

CREATE INDEX aws_role_assignments_role_idx  ON aws_role_assignments(role_id);
CREATE INDEX aws_role_assignments_group_idx ON aws_role_assignments(group_id);

-- aws_revoked_users tracks each (role, user-uuid) the revocation provisioner
-- has added to the role's AuthRevokedUsers inline policy. The reaper trims
-- entries older than the role's max_session_duration — by then every STS
-- session protected by the Deny statement has expired naturally.
CREATE TABLE aws_revoked_users (
    role_id     UUID        NOT NULL REFERENCES aws_roles(id) ON DELETE CASCADE,
    sub_uuid    TEXT        NOT NULL,
    revoked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (role_id, sub_uuid)
);

CREATE INDEX aws_revoked_users_revoked_at_idx ON aws_revoked_users(revoked_at);
