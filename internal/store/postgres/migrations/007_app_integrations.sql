-- app_integrations stores outbound provisioner configurations (Vault SCIM,
-- AWS IAM, etc.) previously sourced from environment variables. The unique
-- `name` column doubles as the external_ids.provider key, so existing
-- external_ids rows survive migration as long as the imported row keeps the
-- legacy provider name (e.g. "vault"). Tokens are envelope-encrypted with the
-- master KEK using crypto.EncryptSecret; encrypted_token is nullable so
-- credential-less providers (AWS IAM uses the SDK's default credential chain)
-- can omit it.
CREATE TABLE app_integrations (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT        NOT NULL UNIQUE,
    provider        TEXT        NOT NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    config          JSONB       NOT NULL DEFAULT '{}',
    encrypted_token BYTEA,
    encrypted_dek   BYTEA,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
