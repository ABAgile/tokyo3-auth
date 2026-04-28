-- external_ids caches each user's downstream-provisioning UUID, keyed by
-- provider. Used by outbound SCIM/IAM provisioners to avoid resolving the
-- downstream user every update. ON DELETE CASCADE keeps the cache consistent
-- with the users table.
CREATE TABLE external_ids (
    provider         TEXT NOT NULL,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    external_user_id TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, user_id)
);

CREATE INDEX external_ids_lookup ON external_ids(provider, external_user_id);
