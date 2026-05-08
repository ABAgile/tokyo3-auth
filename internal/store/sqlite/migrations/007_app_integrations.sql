-- app_integrations stores outbound provisioner configurations (Vault SCIM,
-- AWS IAM, etc.) previously sourced from environment variables. The unique
-- `name` column doubles as the external_ids.provider key, so existing
-- external_ids rows survive migration as long as the imported row keeps the
-- legacy provider name (e.g. "vault"). Tokens are envelope-encrypted with the
-- master KEK using crypto.EncryptSecret; encrypted_token is nullable so
-- credential-less providers (AWS IAM uses the SDK's default credential chain)
-- can omit it.
CREATE TABLE app_integrations (
    id              TEXT     PRIMARY KEY,
    name            TEXT     NOT NULL UNIQUE,
    provider        TEXT     NOT NULL,
    enabled         INTEGER  NOT NULL DEFAULT 1,
    config          TEXT     NOT NULL DEFAULT '{}',
    encrypted_token BLOB,
    encrypted_dek   BLOB,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
