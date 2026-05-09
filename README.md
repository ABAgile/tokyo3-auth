# auth

[![Release](https://img.shields.io/github/v/release/abagile/tokyo3-auth?sort=semver&logo=Go&color=%23007D9C)](https://github.com/abagile/tokyo3-auth/releases)
[![Test](https://github.com/abagile/tokyo3-auth/actions/workflows/test.yml/badge.svg)](https://github.com/abagile/tokyo3-auth/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abagile/tokyo3-auth.svg)](https://pkg.go.dev/github.com/abagile/tokyo3-auth)
[![Go Report Card](https://goreportcard.com/badge/github.com/abagile/tokyo3-auth)](https://goreportcard.com/report/github.com/abagile/tokyo3-auth)
[![codecov](https://codecov.io/gh/abagile/tokyo3-auth/branch/main/graph/badge.svg)](https://codecov.io/gh/abagile/tokyo3-auth)

A minimal self-hosted Identity Provider (IdP) for internal applications.

## Overview

`auth` acts as an OAuth2/OIDC authorization server with four pillars:

1. **OAuth2/OIDC** — Authorization Code + PKCE (S256), ID tokens (RS256), JWKS rotation, UserInfo, token revocation.
2. **GitHub OAuth compatibility** — Drop-in replacement for GitHub OAuth so existing integrations work without code changes.
3. **Outbound provisioning** — auth pushes user/group lifecycle events to downstream systems via SCIM 2.0 (Vault, Okta-as-target, custom REST) and the AWS IAM SDK. Per-integration auth is bearer token *or* mTLS (mutually exclusive).
4. **PCI-DSS v4.0.1 policy engine** — Pluggable rule engine enforcing password complexity, MFA, lockout, session timeout, and audit logging.

## Design Concepts

### Token model
- **Access tokens**: Opaque random 32-byte hex strings. SHA-256 hashes stored in the database. Never stored in plain text.
- **Refresh tokens**: Same opaque model; rotated on each use.
- **ID tokens**: RS256 JWT with OIDC Core 1.0 claims (`sub`, `iss`, `aud`, `exp`, `iat`, `email`, `name`, `nonce`, `auth_time`, `acr`, `amr`).
- **Code grant**: 10-minute authorization codes; single-use; PKCE S256 verified at exchange.

### Policy engine
The `internal/policy` package provides a pluggable `Rule` interface. PCI-DSS v4.0.1 rules are loaded by default:

| Rule | Requirement | Enforcement |
|------|-------------|-------------|
| `PasswordComplexityRule` | 8.3.6 | ≥12 chars, upper+lower+digit+special |
| `PasswordAgeRule` | 8.3.9 | Password expires after 90 days when MFA is disabled |
| `AccountLockoutRule` | 8.3.4 | Lock after 10 consecutive failures for 30 minutes |
| `MFARequiredRule` | 8.4.2 | Block token issuance without MFA verification |
| `SessionIdleTimeoutRule` | 8.2.8 | 15-minute idle timeout for `cde` scoped sessions |
| `TokenLifetimeRule` | 8.2.8 | Access tokens: 1h max; refresh tokens: 24h max |
| `ClientSecretAgeRule` | 8.6.1 | Machine client secrets must be rotated every 12 months |

### MFA
- **TOTP**: RFC 6238 (SHA1, 6-digit, 30s), ±1 window skew. Secret encrypted with AES-256-GCM DEK+KEK.
- **WebAuthn/FIDO2**: `go-webauthn/webauthn` library. Supports biometric devices and YubiKeys. Session data stored in DB with 5-minute TTL.

### Audit
Every authentication event writes an `AuditLog` row in the local auth DB and is published to a NATS JetStream stream (`auth_audit` on subject `auth.audit.events`). Failures are recorded even when the overall operation fails (fail-closed pattern). Structured JSON logs via `log/slog`.

The JetStream stream is the authoritative, tamper-resistant record (FileStorage, DenyDelete, DenyPurge, 13-month retention floor for PCI-DSS 10.5). A separate `auth-audit` binary subscribes to the stream and projects events into a dedicated audit Postgres database — the auth process cannot read or mutate this projection.

| Identity | Subject perms | DB perms |
| --- | --- | --- |
| `authd-nats-client` (publisher) | PUBLISH `auth.audit.events` | (n/a) |
| `auth-audit-nats-client` (consumer) | SUBSCRIBE + consumer mgmt | (n/a) |
| `auth-audit-db-client` | (n/a) | DDL + INSERT + SELECT on `auth_audit.audit_logs` |

Operating the pipeline:

```
make docker-up                              # nats + natsbox + audit-db + auth-audit + auth all wired up
docker compose exec natsbox nats stream info auth_audit
docker compose exec natsbox nats sub 'auth.audit.events'
docker compose exec auth-audit auth-audit query --action auth.login --limit 20
```

Required env vars on `authd` to enable JetStream publishing: `AUTH_NATS_URL`, plus `AUTH_NATS_CERT/KEY/CA` for mTLS. With `AUTH_NATS_URL` unset, audit publishing is disabled and only the local DB write happens (still fine for dev).

### Outbound provisioning
Authoritative user/group mutations (admin API, portal admin actions, self-registration) fan out to every enabled integration. SCIM targets receive standards-compliant SCIM 2.0 calls; AWS IAM targets translate group display names to IAM groups via a configurable map. The OIDC discovery endpoint enables `AssumeRoleWithWebIdentity` federation.

### Crypto
- Passwords: bcrypt cost 12.
- Opaque tokens: 32-byte random hex, SHA-256 hash stored.
- TOTP secrets + JWT private keys: AES-256-GCM with DEK+KEK envelope. DEK per value, KEK from `AUTH_MASTER_KEY`.
- Auth state cookies (login→MFA flow): AES-256-GCM with master key directly (short-lived, no rotation needed).

## Requirements

- Go 1.22+
- PostgreSQL 15+
- (Optional) AWS credentials for IAM provisioning

## Installation

```bash
go install github.com/abagile/tokyo3-auth/cmd/authd@latest
```

Or build from source:

```bash
git clone <repo>
cd auth
go build -o authd ./cmd/authd
```

### Database setup

```bash
# Generate a master key (save this securely)
./authd keygen

# Run migrations
AUTH_ADMIN_DATABASE_URL="postgres://admin:pass@localhost/authdb" ./authd migrate
```

### Bootstrap first admin user

```bash
AUTH_DATABASE_URL="postgres://app:pass@localhost/authdb" \
  ./authd admin user create \
    --email admin@example.com \
    --password "S3cur3P@ssw0rd!" \
    --name "Admin"
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTH_ISSUER` | Yes | — | IdP base URL, e.g. `https://id.example.com` |
| `AUTH_ADDR` | No | `:8443` | HTTPS listen address (`host:port`; empty host = all interfaces) |
| `AUTH_DATABASE_URL` | Yes | — | PostgreSQL DSN (app role, DML only) |
| `AUTH_ADMIN_DATABASE_URL` | No | `AUTH_DATABASE_URL` | PostgreSQL DSN for migrations (DDL) |
| `AUTH_MASTER_KEY` | Yes | — | 64-hex-char KEK for TOTP secrets + JWT key encryption |
| `AUTH_ALLOW_REGISTRATION` | No | `false` | Set to `true` to enable self-registration at `/register` |
| `AUTH_AWS_IAM_ENABLED` | No | `false` | Deprecated. Configure AWS IAM via `/portal/admin/integrations` instead. |
| `AUTH_VAULT_SCIM_ENABLED` | No | `false` | Deprecated. Configure Vault SCIM via `/portal/admin/integrations` instead. Auto-imported into `app_integrations` once on first boot when set (always as bearer-mode). |
| `AUTH_VAULT_SCIM_URL` | No | — | Deprecated; auto-imported on first boot. |
| `AUTH_VAULT_SCIM_TOKEN` | No | — | Deprecated; auto-imported on first boot. |
| `AUTH_VAULT_SCIM_TIMEOUT` | No | `10s` | Deprecated; auto-imported on first boot. |
| `AUTH_SCIM_CERT` | If any mTLS integration | — | Client cert PEM path for mTLS-mode integrations. Hot-reloaded (mtime polled at most once per second across SCIM requests). |
| `AUTH_SCIM_KEY` | If any mTLS integration | — | Client key PEM. Required iff `AUTH_SCIM_CERT` is set. |
| `AUTH_SCIM_CA` | No | system roots | CA bundle PEM for verifying downstream SCIM servers. |
| `AUTH_WEBAUTHN_ORIGINS` | No | Derived from `AUTH_ISSUER` | Space-separated additional WebAuthn origins |
| `AWS_REGION` | If IAM enabled | — | AWS region |
| `AWS_ACCESS_KEY_ID` | If IAM enabled | — | AWS credentials (or use instance role) |
| `AWS_SECRET_ACCESS_KEY` | If IAM enabled | — | AWS credentials |

## Running

```bash
AUTH_ISSUER=https://id.example.com \
AUTH_DATABASE_URL="postgres://app:pass@localhost/authdb" \
AUTH_MASTER_KEY="$(./authd keygen)" \
./authd serve
```

### CLI commands

| Command | Description |
|---------|-------------|
| `authd serve` | Start the HTTP server |
| `authd migrate` | Apply pending database migrations |
| `authd keygen` | Generate a random 32-byte master key |
| `authd admin user create` | Create an admin user |
| `authd admin sync --target=<name\|all>` | Backfill an integration (configured via `/portal/admin/integrations`) from auth's tables |

## Endpoint Reference

### OAuth2/OIDC

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | OIDC discovery document |
| `GET` | `/.well-known/jwks.json` | Public key set (RS256) |
| `GET` | `/authorize` | Show login form |
| `POST` | `/authorize` | Submit credentials |
| `POST` | `/authorize/mfa/totp` | Submit TOTP code during login |
| `GET` | `/authorize/mfa/webauthn` | WebAuthn MFA page during OAuth2 flow |
| `POST` | `/authorize/mfa/webauthn/begin` | Begin WebAuthn assertion (SSO MFA step) |
| `POST` | `/authorize/mfa/webauthn/finish` | Complete WebAuthn assertion, issue code |
| `GET/POST` | `/register` | Self-registration form (requires `AUTH_ALLOW_REGISTRATION=true`) |
| `POST` | `/token` | Token exchange (authorization_code, refresh_token, client_credentials) |
| `GET` | `/userinfo` | UserInfo endpoint (Bearer token required) |
| `POST` | `/revoke` | Token revocation (RFC 7009) |

### GitHub OAuth Compatibility

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/login/oauth/authorize` | GitHub-style authorization redirect |
| `POST` | `/login/oauth/access_token` | Token exchange (JSON or form-encoded, per `Accept` header) |
| `GET` | `/api/v3/user` | User info in GitHub API v3 shape |
| `GET` | `/api/v3/user/emails` | User emails list |

To use an existing GitHub OAuth app with this IdP:
1. Set the app's Authorization callback URL to `https://your-app/github/callback`
2. Set the app's Homepage URL to your application
3. Point `GITHUB_API_URL` / equivalent in your app to this IdP's base URL

### MFA

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/mfa/totp/enroll` | Bearer | Generate TOTP secret + QR URI |
| `POST` | `/mfa/totp/confirm` | Bearer | Verify first code to activate TOTP |
| `POST` | `/mfa/totp/verify` | Bearer | Verify TOTP code |
| `DELETE` | `/mfa/totp` | Bearer | Remove TOTP credential |
| `POST` | `/mfa/webauthn/register/begin` | Bearer | Start WebAuthn credential registration |
| `POST` | `/mfa/webauthn/register/finish?session_id=...&device_name=...` | Bearer | Complete registration |
| `POST` | `/mfa/webauthn/login/begin` | None | Start WebAuthn assertion (body: `{"email":"..."}`) |
| `POST` | `/mfa/webauthn/login/finish?session_id=...&user_id=...` | None | Complete assertion |
| `DELETE` | `/mfa/webauthn/{id}` | Bearer | Remove a WebAuthn credential |

### Admin API

All admin endpoints require a Bearer token belonging to a session with the `admin` scope.

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/admin/users` | List / create users |
| `GET/PUT/DELETE` | `/admin/users/{id}` | Get / update / delete user |
| `GET/POST` | `/admin/clients` | List / create OAuth2 clients |
| `GET/DELETE` | `/admin/clients/{id}` | Get / delete client |
| `POST` | `/admin/clients/{id}/rotate-secret` | Rotate client secret |
| `GET` | `/admin/audit` | Query audit logs (`?limit=100&offset=0`) |

### Portal (Web UI)

The portal is a server-rendered web UI for user self-service and admin management. It uses an encrypted `portal_tok` HttpOnly cookie (AES-256-GCM) backed by a regular session in the database.

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/portal/login` | Portal sign-in form (email + password) |
| `GET/POST` | `/portal/login/mfa` | TOTP MFA step during portal sign-in |
| `POST` | `/portal/logout` | Sign out (deletes session) |
| `GET` | `/portal` | Account overview |
| `GET` | `/portal/account` | Profile & password settings |
| `POST` | `/portal/account/profile` | Update display name |
| `POST` | `/portal/account/password` | Change password |
| `GET` | `/portal/mfa` | MFA enrollment (TOTP + WebAuthn) |
| `POST` | `/portal/mfa/totp/enroll` | Start TOTP enrollment (stores QR data in cookie) |
| `POST` | `/portal/mfa/totp/confirm` | Confirm first TOTP code to activate |
| `POST` | `/portal/mfa/totp/delete` | Remove TOTP credential |
| `POST` | `/portal/mfa/webauthn/register/begin` | Begin WebAuthn key registration (cookie auth) |
| `POST` | `/portal/mfa/webauthn/register/finish` | Complete WebAuthn registration |
| `POST` | `/portal/mfa/webauthn/{id}/delete` | Remove a WebAuthn credential |

**Admin panel** (requires `is_admin = true` on the user's account):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/portal/admin/users` | List users |
| `GET/POST` | `/portal/admin/users/new` | Create user |
| `GET/POST` | `/portal/admin/users/{id}/edit` | Edit user (name, active, **admin role**) |
| `POST` | `/portal/admin/users/{id}/delete` | Delete user |
| `GET` | `/portal/admin/groups` | List groups (roles) |
| `GET/POST` | `/portal/admin/groups/new` | Create group + assign members |
| `GET/POST` | `/portal/admin/groups/{id}/edit` | Edit group display name + membership |
| `POST` | `/portal/admin/groups/{id}/delete` | Delete group (members are not deleted) |
| `GET` | `/portal/admin/clients` | List OAuth clients |
| `GET/POST` | `/portal/admin/clients/new` | Create OAuth client |
| `GET/POST` | `/portal/admin/clients/{id}/edit` | Edit client |
| `POST` | `/portal/admin/clients/{id}/delete` | Delete client |
| `POST` | `/portal/admin/clients/{id}/rotate-secret` | Rotate client secret |
| `GET` | `/portal/admin/integrations` | List app integrations (Vault SCIM, AWS IAM, …) |
| `GET/POST` | `/portal/admin/integrations/new` | Add a new integration |
| `GET/POST` | `/portal/admin/integrations/{id}/edit` | Edit integration; rotate token |
| `POST` | `/portal/admin/integrations/{id}/delete` | Remove integration |
| `POST` | `/portal/admin/integrations/{id}/test` | Probe SCIM ServiceProviderConfig using the integration's auth mode |
| `GET` | `/portal/admin/audit` | Browse audit log (paginated) |

**Role assignment:** Two layers of role management are available:

- **Portal admin flag** — toggle the "Administrator" checkbox on any user's edit page. Grants access to `/portal/admin/*`. Effective on next portal login.
- **Application roles via groups** — create groups under `/portal/admin/groups`, assign users, and the same group is fanned out to every enabled integration as a SCIM `Group` (or AWS IAM group via the integration's group map). Saving the group triggers an immediate downstream sync.

### Health

```
GET /health  →  200 OK
```

## GitHub OAuth Compatibility

Point existing GitHub OAuth integrations at this IdP by setting the authorization and token endpoints:

```
Authorization URL: https://id.example.com/login/oauth/authorize
Token URL:         https://id.example.com/login/oauth/access_token
API base URL:      https://id.example.com/api/v3
```

The GitHub-compatible user object maps:
- `id` — stable integer derived from user UUID (FNV-64a hash)
- `login` — local part of email address
- `name` — user display name
- `email` — primary email

## AWS IAM Integration

### Register this IdP as an OIDC provider

```bash
aws iam create-open-id-connect-provider \
  --url https://id.example.com \
  --thumbprint-list <cert-thumbprint> \
  --client-id-list sts.amazonaws.com
```

### Configure AssumeRoleWithWebIdentity

Attach a trust policy to your IAM role:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::ACCOUNT:oidc-provider/id.example.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {"id.example.com:aud": "your-client-id"}}
  }]
}
```

### IAM provisioning setup

Add an `aws_iam` integration at `/portal/admin/integrations/new` to enable automatic IAM user creation when users/groups change in auth (admin API or portal). Credentials come from the AWS SDK default credential chain on the host running authd. SCIM display name → IAM group name mapping is configured per-integration via the `Group mapping` field.

## Outbound provisioning

Auth fans out user and group lifecycle events to downstream systems whenever an authoritative mutation occurs — inbound SCIM, the admin API, self-registration, and the portal admin actions all trigger the same fan-out. Each downstream is a `provision.Provisioner` (`internal/provision/`); failures are logged but never block the originating request.

Integrations are persisted in the `app_integrations` table and managed via `/portal/admin/integrations`. Saving or deleting an integration **hot-reloads** the in-memory provisioner registry — changes take effect immediately, no restart required. SCIM bearer tokens are envelope-encrypted with the master KEK (same DEK+KEK pattern as TOTP secrets); only `name`, `provider`, and the non-secret JSON config are queryable.

Multiple rows of the same provider type are allowed (e.g. `vault-prod` + `vault-staging`). The integration `name` doubles as the cache key for `external_ids`, so do not rename a live integration — add a new one and disable/delete the old one instead.

> See [`docs/integration-guide.md`](docs/integration-guide.md) for the full bring-up runbook (auth ↔ vault) and the recipe for adding any new SCIM/REST-capable downstream app.

### Vault SCIM (auth as IdP for vault)

Vault is the canonical example: auth pushes users and groups to vault's SCIM server so vault membership stays in lockstep with auth's identity. Pick *one* of the two auth modes below — they're mutually exclusive per integration.

#### Option A — Bearer token (SaaS-friendly, simplest)

**1. Mint a SCIM token in vault**:
```
POST $VAULT/api/v1/scim/tokens
Authorization: Bearer <vault server-admin token>
{ "description": "auth -> vault provisioner" }
```
The response includes the raw token once — store it.

**2. Add a Vault SCIM integration** at `/portal/admin/integrations/new`:
- Name: `vault` (or any unique identifier; see note above)
- Provider: `scim`
- Base URL: `https://vault.example.com/scim/v2`
- Authentication: `Bearer token`
- Token: paste the value from step 1
- Enabled: yes

#### Option B — mTLS (no token bootstrap; cert infra required)

**1. Configure vault** to require client certs on `/scim/v2/*` and allow-list auth's CA + the SAN/CN that identifies authd. Vault verifies the cert at the TLS handshake; no SCIM token needed.

**2. Set the env vars on the authd process**:
```
AUTH_SCIM_CERT=/run/secrets/auth-outbound.crt
AUTH_SCIM_KEY=/run/secrets/auth-outbound.key
AUTH_SCIM_CA=/run/secrets/downstream-ca.crt   # optional; falls back to system roots
```
The cert file is hot-reloaded — pair this with tbot/cert-manager/SPIFFE for automatic rotation.

**3. Add the integration** the same way as Option A, but pick `mTLS (client cert)` for Authentication. The token field disappears; the cert/key/CA come from the env vars above (one shared identity for every mTLS integration).

After either option: register vault as an OAuth2 client (for SSO; see "Vault SSO" below) and click **Test** on the integration row to confirm authd can reach the SCIM endpoint before sending real traffic.

**4. Backfill existing users** (one-time, after first deployment or when recovering from drift):
```
authd admin sync --target=vault     # by integration name
authd admin sync --target=all       # every enabled integration
```
Iterates auth's `users` and `scim_groups` tables and pushes them. Idempotent — vault's SCIM POST returns the existing record on duplicate email.

**Legacy env vars**: `AUTH_VAULT_SCIM_ENABLED`/`URL`/`TOKEN`/`TIMEOUT` are deprecated. On the first boot after upgrading, if `app_integrations` is empty and `AUTH_VAULT_SCIM_ENABLED=true`, authd auto-imports the env vars into a row named `vault` and logs a deprecation warning. Subsequent boots ignore the env vars entirely — manage the row via the portal.

**Self-heal**: external_ids is a best-effort cache. On a 404 from PUT/PATCH/DELETE the client invalidates the cache, re-resolves via `filter=externalId eq` (vault's Phase 2 filter subset), then either retries or falls through to POST (vault's POST is idempotent on email).

### Vault SSO (vault uses auth as OIDC provider)

1. Register vault as an OAuth2 client:
   ```
   POST /admin/clients
   {
     "name": "vault",
     "redirect_uris": ["https://vault.example.com/api/v1/auth/oidc/callback"],
     "scopes": ["openid", "email", "profile", "offline_access"],
     "public": false
   }
   ```
2. Configure vault env: `VAULT_OIDC_ISSUER`, `VAULT_OIDC_CLIENT_ID`, `VAULT_OIDC_CLIENT_SECRET`, `VAULT_OIDC_REDIRECT_URI`, optionally `VAULT_OIDC_ENFORCE=true`.
3. Vault CLI: `vault login --oidc` opens the browser to auth, captures the session token via a loopback listener, and persists it. `--manual` for SSH/headless cases.

## PCI-DSS v4.0.1 Notes

This service satisfies the following PCI-DSS v4.0.1 requirements in the Cardholder Data Environment (CDE):

| Requirement | Control |
|-------------|---------|
| 8.2.1 | Unique user identifiers enforced (email uniqueness at registration) |
| 8.2.8 | 15-minute idle timeout for CDE-scoped sessions |
| 8.3.4 | Account lockout after 10 failed attempts, 30-minute lock duration |
| 8.3.6 | Password complexity: ≥12 chars, upper+lower+digit+special |
| 8.3.9 | Password age: 90-day maximum when MFA is not enabled |
| 8.4.2 | MFA required for all access to CDE (non-public clients) |
| 8.5.1 | TOTP codes single-use; WebAuthn sign count validated and incremented |
| 8.6.1 | Machine client secrets flagged when older than 12 months |
| 10.2.1 | All auth events, failures, and privilege changes logged to `audit_logs` |

Evidence for each control is available in the `audit_logs` table and the policy engine rule set in `internal/policy/pci.go`.

## MFA Setup

### TOTP enrollment

```bash
# 1. Enroll (returns secret + OTP URI for QR code)
curl -X POST https://id.example.com/mfa/totp/enroll \
  -H "Authorization: Bearer <access-token>"

# 2. Confirm (verify first code from authenticator app)
curl -X POST https://id.example.com/mfa/totp/confirm \
  -H "Authorization: Bearer <access-token>" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```

### WebAuthn registration

```javascript
// 1. Begin registration (get challenge)
const { options, session_id } = await fetch('/mfa/webauthn/register/begin', {
  method: 'POST',
  headers: { 'Authorization': 'Bearer ' + token }
}).then(r => r.json());

// 2. Authenticate with device, then finish
const credential = await navigator.credentials.create({ publicKey: options });
await fetch(`/mfa/webauthn/register/finish?session_id=${session_id}&device_name=MyYubiKey`, {
  method: 'POST',
  headers: { 'Authorization': 'Bearer ' + token },
  body: JSON.stringify(credential)
});
```

## Development

### Local PostgreSQL

```bash
docker run -d --name authdb -p 5432:5432 \
  -e POSTGRES_PASSWORD=secret -e POSTGRES_DB=authdb postgres:15
```

### Running locally

```bash
export AUTH_ISSUER=http://localhost:8080
export AUTH_DATABASE_URL="postgres://postgres:secret@localhost/authdb?sslmode=disable"
export AUTH_MASTER_KEY="$(go run ./cmd/authd keygen)"
go run ./cmd/authd serve
```

### Code quality

```bash
gofmt -s -w .
go test ./...
go vet ./...
staticcheck ./...
find . -type f -name "*.go" -print0 | xargs -0 -n 100 gopls check -severity=hint
govulncheck ./...
```
