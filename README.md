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

### Portal UI

The server-rendered portal adopts the visual identity and design tokens defined
in [`DESIGN.md`](DESIGN.md).

### Token model
- **Access tokens**: Opaque random 32-byte hex strings. SHA-256 hashes stored in the database. Never stored in plain text.
- **Refresh tokens**: Same opaque model; rotated on each use.
- **ID tokens**: RS256 JWT with OIDC Core 1.0 claims (`sub`, `iss`, `aud`, `exp`, `iat`, `email`, `name`, `nonce`, `auth_time`, `acr`, `amr`). `groups` (SCIM group display names) is emitted when the RP requests the `groups` scope — useful for RPs that map roles from a team/group claim (OpenSearch Security `backend_roles`, Vault JWT `claim_mappings`, etc.).
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
Every authentication event is published synchronously to a NATS JetStream stream (`auth_audit` on subject `auth.audit.events`). The publish is **fail-closed**: if the journal is unreachable (NATS down, ack timeout, etc.) every handler that emits an audit event returns 503 and the originating action is refused. The JetStream stream is the **sole** authoritative store — there is no projection database, no local DB mirror. FileStorage + DenyDelete + DenyPurge + 13-month retention satisfy PCI-DSS 10.5.

The same stream is read back by:

- **`/portal/admin/audit`** — live tail in the browser via SSE (last 100 + tail forward, with `Last-Event-ID` reconnect resume).
- **`authd audit query`** — terminal viewer; prints the most recent N events as one JSON object per line, then exits.

Both readers use `journal/jetstream.Source` from `tokyo3-base`; same primitive, different framing.

| Identity | Subject perms |
| --- | --- |
| `authd-nats-client` | PUBLISH + CONSUME on `auth.audit.events` |

Operating the journal:

```
make docker-up                              # standalone Docker stack
# or, after `cd ../ca && make docker-up`, use the shared certd-rooted mesh:
make docker-up-mesh                         # authd on tokyo3_backplane/tokyo3_idp
docker compose exec natsbox nats stream info auth_audit
docker compose exec natsbox nats sub 'auth.audit.events'
docker compose exec authd authd audit query --limit 20
```

Required env vars on `authd` to enable JetStream publish + read: `AUTHD_NATS_URL`, plus `AUTHD_NATS_CERT/KEY/CA` for mTLS. With `AUTHD_NATS_URL` unset, audit publishing is a no-op (dev only) and the live tail page renders empty.

The same NATS endpoint also receives **operational log shipping** — every structured log line authd emits is fanned out to subject `app_log.authd` (alongside stdout). Reuses the same `AUTHD_NATS_*` env vars; ships nothing when `AUTHD_NATS_URL` is unset. The shipper dials with `RetryOnFailedConnect(true)` so a broker that's down at boot doesn't fail process startup — entries drop on the floor (200-entry discard-on-full buffer) while disconnected and resume on reconnect.

### Outbound provisioning
Authoritative user/group mutations (admin API, portal admin actions, self-registration) fan out to every enabled integration. SCIM targets receive standards-compliant SCIM 2.0 calls; AWS IAM targets translate group display names to IAM groups via a configurable map. The OIDC discovery endpoint enables `AssumeRoleWithWebIdentity` federation.

### Crypto
- Passwords: bcrypt cost 12.
- Opaque tokens: 32-byte random hex, SHA-256 hash stored.
- TOTP secrets + JWT private keys: AES-256-GCM with DEK+KEK envelope. DEK per value, KEK from `AUTHD_MASTER_KEY`.
- Auth state cookies (login→MFA flow): AES-256-GCM with master key directly (short-lived, no rotation needed).

### Process robustness
The IdP is on the critical path for every production access surface — AWS console SSO, SSH-proxy sessions, vault, every GitHub-OAuth-compatible RP — so a single panic must not take down the process. Three concentric guards:

- **HTTP recover middleware** wraps the whole mux. Per-request panics turn into a structured log line (method, path, remote, stack) and a `500 server_error` to the client. `http.ErrAbortHandler` is re-panicked so net/http's documented "abort without logging" sentinel still works.
- **Background-goroutine recover** wraps every long-lived spawn — periodic provision sync, AWS-federation revocation reaper, device-grant reaper, and per-RP back-channel-logout pushes. Each reaper's per-tick body is wrapped separately so a single bad tick doesn't kill the loop.
- **Graceful shutdown on listener failure** — if `ListenAndServeTLS` returns an unexpected error (bind conflict, fd exhaustion), the server goroutine signals `cancel()` and lets `runServe`'s defers run: auditSink flushes any in-flight JetStream acks, the DB pool closes, the operational-log NATS connection drains. Previously this path called `os.Exit(1)` and dropped pending audit events.

Slowloris defense via `ReadHeaderTimeout=10s`, `ReadTimeout=60s`, `IdleTimeout=120s` on the HTTP server. `WriteTimeout` is intentionally `0` because the `/portal/admin/audit/sse` stream needs to hold a response open indefinitely; SSE-style handlers that want per-frame deadlines should use `http.ResponseController.SetWriteDeadline`. TLS handshake errors and broken-pipe writes route through `http.Server.ErrorLog` into the structured logger, not stderr.

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

### Docker images

Tagged releases push two images to GHCR:

| Image | Contents | Typical use |
| --- | --- | --- |
| `ghcr.io/abagile/tokyo3-auth` | `authd` server | Run the IdP itself; `docker run` + the env vars in [Configuration](#configuration) |
| `ghcr.io/abagile/tokyo3-auth-cli` | `auth-aws-creds` helper | CI runners and dev containers that prefer a containerized binary over `go install` |

The CLI image has no `ENTRYPOINT` — invoke the binary explicitly so the image can grow more tools later without breaking existing invocations:

```bash
docker run --rm ghcr.io/abagile/tokyo3-auth-cli auth-aws-creds login --issuer https://id.example.com --client-id tokyo3-cli
```

Both images are multi-arch (`linux/amd64`, `linux/arm64`). Tags follow semver (`{{version}}`, `{{major}}.{{minor}}`, `{{major}}`, `latest`) on git tag pushes; commit-SHA tags on every build for traceability.

The SSH-cert counterpart, `auth-ssh-creds`, lives in the [tokyo3-ca](https://github.com/abagile/tokyo3-ca) repo because its wire shape tracks certd's `/api/v1/ssh/sign-user` endpoint (SSO is the prerequisite, not the contract it has to stay in sync with). Its CLI image is `ghcr.io/abagile/tokyo3-ca-cli`; both helpers read the same shared `~/.config/auth-sso/` SSO cache, so one `auth-aws-creds login` (or `auth-ssh-creds login`) populates the cache for both.

### Database setup

```bash
# Generate a master key (save this securely)
./authd keygen

# Run migrations
AUTHD_ADMIN_DATABASE_URL="postgres://admin:pass@localhost/authd" ./authd migrate
```

### Bootstrap first admin user

```bash
AUTHD_DATABASE_URL="postgres://app:pass@localhost/authd" \
  ./authd admin user create \
    --email admin@example.com \
    --password "S3cur3P@ssw0rd!" \
    --name "Admin"
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AUTHD_ISSUER` | Yes | — | IdP base URL, e.g. `https://id.example.com` |
| `AUTHD_ADDR` | No | `:8443` | HTTPS listen address (`host:port`; empty host = all interfaces) |
| `AUTHD_DATABASE_URL` | Yes | — | PostgreSQL DSN (app role, DML only) |
| `AUTHD_ADMIN_DATABASE_URL` | No | `AUTHD_DATABASE_URL` | PostgreSQL DSN for migrations (DDL) |
| `AUTHD_DB_CERT` | If Postgres requires mTLS | — | Client cert PEM path for the runtime DB pool. The leaf is re-read on every TLS handshake (via `tls/reloader`), so a rotated file is picked up by the next pool dial — `SetConnMaxLifetime` is 5m so pooled conns recycle within that window. |
| `AUTHD_DB_KEY` | If `AUTHD_DB_CERT` is set | — | Client key PEM, reloaded together with `AUTHD_DB_CERT` on every handshake. |
| `AUTHD_DB_CA` | No | falls back to `AUTHD_WORKLOAD_CA` | CA bundle PEM for verifying the Postgres server cert. Trust pool is re-read on mtime change and verified per handshake via `VerifyConnection`. |
| `AUTHD_ADMIN_DB_CERT` / `AUTHD_ADMIN_DB_KEY` / `AUTHD_ADMIN_DB_CA` | If migrate uses a separate role with mTLS | falls back to `AUTHD_DB_*` (CA also falls back to `AUTHD_WORKLOAD_CA`) | mTLS material for the migrate (DDL) connection. **Not** hot-reloaded — the connection closes after migrations finish, so rotation isn't relevant on this path. |
| `AUTHD_MASTER_KEY` | Yes | — | 64-hex-char KEK, or `file:<path>` to read one from disk, for TOTP secrets + JWT key encryption |
| `AUTHD_ALLOW_REGISTRATION` | No | `false` | Set to `true` to enable self-registration at `/register` |
| `AUTHD_PROVISION_SYNC_INTERVAL` | No | `1h` | Period for the background full-sync goroutine that re-pushes every user/group to every enabled integration. Belt-and-suspenders for the event-driven push path; idempotent per tick. Set to `0` (or any negative duration) to disable. |
| `AUTHD_AWS_AUDIENCE` | If using AWS federation | — | Single `aud` value emitted on every JWT minted for AWS console/CLI federation. Register the same string as `--client-id-list` on each AWS account's IAM OIDC provider. Empty disables the federation flow (AWS tiles on the portal home won't launch and `/aws/credentials` returns 503). Per-role gating happens via `aws:RequestTag/<key>` conditions, not per-role audiences. |
| `AUTHD_STEP_UP_MFA_TTL` | No | `5m` | Freshness window for the step-up MFA gate that protects AWS roles flagged `require_step_up_mfa`. A click on such a role re-prompts MFA when the session's last MFA challenge is older than this duration (or never happened). Accepts any `time.ParseDuration` value (`30s`, `10m`, `1h`); invalid or empty values fall back to `5m`. |
| `AUTHD_AWSFED_REAP_INTERVAL` | No | `6h` | Period for the AWS federation revocation reaper. Trims `aws_revoked_users` entries past each role's `MaxSessionDuration` and re-pushes the trimmed inline policy. No-op when no `aws_federation` integration is enabled. Set to `0` to disable. |
| `AUTHD_VAULT_SCIM_ENABLED` | No | `false` | Deprecated. Configure Vault SCIM via `/portal/admin/integrations` instead. Auto-imported into `app_integrations` once on first boot when set (always as bearer-mode). |
| `AUTHD_VAULT_SCIM_URL` | No | — | Deprecated; auto-imported on first boot. |
| `AUTHD_VAULT_SCIM_TOKEN` | No | — | Deprecated; auto-imported on first boot. |
| `AUTHD_VAULT_SCIM_TIMEOUT` | No | `10s` | Deprecated; auto-imported on first boot. |
| `AUTHD_NATS_URL` | If JetStream audit publishing is required | — | NATS server URL for audit publish + read **and** operational log shipping. Empty disables audit publishing (no-op sink), the live tail page renders empty, and `app_log.authd` shipping silently no-ops. |
| `AUTHD_NATS_CERT` | If NATS requires mTLS | falls back to `AUTHD_WORKLOAD_CERT` | Client cert PEM path shared by the audit sink + source **and** the operational-log shipper. The leaf is re-read from disk on every TLS handshake (via `tls/reloader`), so a rotated file is picked up on the next NATS reconnect — no daemon restart. |
| `AUTHD_NATS_KEY` | If `AUTHD_NATS_CERT` is set | falls back to `AUTHD_WORKLOAD_KEY` | Client key PEM, reloaded together with `AUTHD_NATS_CERT` on every handshake. |
| `AUTHD_NATS_CA` | No | falls back to `AUTHD_WORKLOAD_CA` | CA bundle PEM for verifying the NATS server cert. Trust pool is re-read on mtime change and verified per handshake via `VerifyConnection`. |
| `AUTHD_SCIM_MTLS_CERT` | If any mTLS integration | — | Client cert PEM path for mTLS-mode integrations. Hot-reloaded (mtime polled at most once per second across SCIM requests). |
| `AUTHD_SCIM_MTLS_KEY` | If any mTLS integration | — | Client key PEM. Required iff `AUTHD_SCIM_MTLS_CERT` is set. |
| `AUTHD_SCIM_MTLS_CA` | No | falls back to `AUTHD_WORKLOAD_CA`, then system roots | CA bundle PEM for verifying downstream SCIM servers. |
| `AUTHD_WORKLOAD_CA` | No | — | Single workload CA root used as the fallback for every per-channel CA env var (`AUTHD_DB_CA`, `AUTHD_ADMIN_DB_CA`, `AUTHD_NATS_CA`, `AUTHD_SCIM_MTLS_CA`). Set this alone in deployments that issue all internal certs from one CA; set per-channel vars to override individually. |
| `AUTHD_WORKLOAD_CERT` / `AUTHD_WORKLOAD_KEY` | No | — | The daemon's workload mTLS identity. Currently the fallback for `AUTHD_NATS_CERT` / `AUTHD_NATS_KEY`, so a daemon that already carries a workload cert ships audit **and** operational logs over mTLS without a second cert set. Set the `AUTHD_NATS_*` vars only to give NATS a distinct identity. |
| `AUTHD_DEBUG_ADDR` | No | — | Listen address (e.g. `127.0.0.1:6060`) for the opt-in diagnostics server: Go runtime profiles (`/debug/pprof/…`) plus a periodic `runtime stats` log line. Empty disables it entirely. **Unauthenticated — bind to loopback or a private interface, never expose publicly.** |
| `AUTHD_WEBAUTHN_ORIGINS` | No | Derived from `AUTHD_ISSUER` | Space-separated additional WebAuthn origins |
| `AUTHD_WEBAUTHN_RPID` | No | Hostname of `AUTHD_ISSUER` | WebAuthn Relying Party ID override. Set to a registrable parent domain (e.g. `example.com`) so credentials work across sibling subdomains; list each subdomain's full origin in `AUTHD_WEBAUTHN_ORIGINS`. **Changing the RP ID invalidates all previously registered WebAuthn credentials** — users must re-register. |
| `AWS_REGION` | If an `aws_iam` or `aws_federation` integration is enabled | — | Signing region for the AWS SDK's IAM calls (IAM is global but the SDK requires a region; `us-east-1` is canonical). Not read by auth itself — consumed by the AWS SDK Go default credential chain. |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | If neither machine IAM role nor any other credential source is available | — | Standard AWS SDK env vars, **not read by auth**. The SDK's default credential chain (used by the `aws_iam` and `aws_federation` provisioners) picks these up if set. **Prefer a machine IAM role** — EC2 instance profile, ECS task role, EKS IRSA, or IAM Roles Anywhere — over static keys for production. The federation flow (`/portal/aws`, `/aws/credentials`) does NOT need any AWS credentials at all; only the IAM-creates-users provisioner and the federation revocation provisioner do. |

### Cert rotation

authd does not hold long-lived TLS material in memory across rotations on the channels that matter. cert-agentd (or any external rotator: cert-manager, SPIFFE, tbot, manual replace) can drop a fresh cert in place and the next handshake on each channel presents it — no SIGHUP, no restart.

| Channel | Mechanism | Picked up on |
|---|---|---|
| Incoming HTTPS (`AUTHD_API_CERT`) | `tls.Config.GetCertificate` via `reloader.CertLoader` | Every TLS handshake (per-request) |
| SCIM outbound mTLS (`AUTHD_SCIM_MTLS_CERT`) | `tls.Config.GetClientCertificate` via `reloader.CertLoader` | Every outbound SCIM request |
| Postgres pool (`AUTHD_DB_CERT/KEY/CA`) | `reloader.ClientConfig`: `GetClientCertificate` re-reads the leaf per handshake, `VerifyConnection` re-reads the CA pool on mtime | Every new pool dial. `SetConnMaxLifetime` is 5m so existing pooled conns recycle within that window |
| NATS audit sink + source (`AUTHD_NATS_CERT/KEY/CA`) | `reloader.ClientConfig` (via base `cli.AuditSink`/`AuditSource`): leaf re-read per handshake, CA pool re-read on mtime | Every NATS reconnect (the lib auto-reconnects on disconnect) |
| Operational-log shipper (`AUTHD_NATS_CERT/KEY/CA`) | Same `reloader.ClientConfig` path, via base `applog.AppLoggerWithNATS` | Every NATS reconnect |

**Note**: as of `tokyo3-base` v0.7.0 the operational-log shipper (`applog.AppLoggerWithNATS`, same `AUTHD_NATS_*` material) hot-reloads through the same `tls/reloader` path as the audit channels — no boot-pin, no restart needed to roll it onto a rotated cert. (Earlier versions pinned the shipper's cert at boot; that gap is closed.)

What rotation does **not** do: it never disturbs an already-established TLS session. TLS authenticates at handshake time only; the X.509 cert is not consulted again on the wire. So in-flight requests, open NATS subscriptions, and active DB transactions survive a rotation untouched — only subsequent dials see the new material.

## Running

```bash
AUTHD_ISSUER=https://id.example.com \
AUTHD_DATABASE_URL="postgres://app:pass@localhost/authd" \
AUTHD_MASTER_KEY="$(./authd keygen)" \
./authd serve
```

### CLI commands

| Command | Description |
|---------|-------------|
| `authd serve` | Start the HTTP server |
| `authd migrate` | Apply pending database migrations |
| `authd keygen` | Generate a random 32-byte master key for `AUTHD_MASTER_KEY` or a key file |
| `authd admin user create` | Create an admin user |
| `authd admin sync --target=<name\|all>` | Backfill an integration (configured via `/portal/admin/integrations`) from auth's tables |
| `authd audit query [--limit N]` | Print the most recent N audit events from the JetStream journal as JSON (default 100) |

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
| `GET/POST` | `/register` | Self-registration form (requires `AUTHD_ALLOW_REGISTRATION=true`) |
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
| `GET` | `/api/v3/user/orgs` | Synthetic single-org list (login derived from issuer host) — required by Teleport's `github` connector |
| `GET` | `/api/v3/user/teams` | User's SCIM groups projected as teams under the synthetic org |

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

### Portal (Web UI)

The portal is a server-rendered web UI for user self-service and admin management. It uses an encrypted `auth_portal` HttpOnly cookie (AES-256-GCM) backed by a regular session in the database. Idle timeout is **15 minutes sliding** — every authenticated portal hit (or silent SSO via `/authorize`) extends `access_expires_at` and re-issues the cookie's `MaxAge`. No matter how active the user stays, sessions hard-cap at **4 hours** from `created_at` — re-authentication at `/authorize` mints a new row and restarts the clock.

**Session TTLs** (constants in `internal/api/oauth2.go`):

| Window | Value | Slid by |
|---|---|---|
| Access token (`access_expires_at`) | 15 min | portal hits, refresh-token grant |
| Refresh token (`refresh_expires_at`) | 1 hour | refresh-token grant only |
| Absolute (from `created_at`) | 4 hours | never — re-auth required |

`bearerAuth` enforces `now < access_expires_at` AND `now − created_at < 4h`. The OIDC `/token` response's `expires_in` is set to the access window's remaining seconds, so RPs that respect the contract align naturally.

**Silent SSO**: when an OIDC RP redirects a user to `/authorize` and the browser already has a valid `auth_portal` cookie, the request short-circuits — the auth server issues an authorization code immediately without showing the login form. Criteria: cookie decryptable, session not expired, user active, MFA verified (when the user has MFA enabled), `login_hint` (if any) matches, `max_age` (if any) hasn't elapsed, and policy engine raises no violation. OIDC `prompt=login` forces re-auth; `prompt=none` returns `error=login_required` to the RP when no session is usable. Conversely, every successful `/authorize` credential check (password, TOTP, WebAuthn) seats the `auth_portal` cookie *as part of issuing the RP code* — so a user who signs in to an RP for the first time can hit the auth portal afterwards without re-authenticating, and the next RP redirect rides silent SSO automatically.

**User-switch cleanup**: when the same browser authenticates as a different user than the one currently in the `auth_portal` cookie (e.g. user A is still signed in, then user B reaches the login form via `prompt=login` and authenticates), the prior user's sessions are wiped before the new cookie is seated — `DeleteSessionsByUserID(A)` plus a user-scoped back-channel logout so every RP also revokes A's local tokens. Without this, A's session row would be orphaned in the DB and A's vault session would silently keep working under B's browser tab.

**Portal logout = sign out everywhere**: clicking *Sign out* in auth's own portal deletes every session the user holds at auth (the portal session *and* every RP-token session) and broadcasts a user-scoped back-channel logout to every client with a `backchannel_logout_uri` set. The RP then revokes its local session(s) via its sub-based deletion path. This is intentionally a global wipe — the IdP portal is the central control surface; signing out *there* is the user saying "end my SSO altogether." Per-RP local sign-out lives at the RP (vault's `/portal/logout`, etc.) and does not propagate back to auth.

| Method | Path | Description |
|--------|------|-------------|
| `GET/POST` | `/portal/login` | Portal sign-in form (email + password) |
| `GET/POST` | `/portal/login/mfa` | TOTP MFA step during portal sign-in |
| `POST` | `/portal/logout` | Sign out (deletes session) |
| `GET` | `/portal` | Account overview |
| `GET` | `/portal/account` | Profile (display name, password change, TOTP + WebAuthn enrollment) |
| `POST` | `/portal/account/profile` | Update display name |
| `POST` | `/portal/account/password` | Change password |
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
| `GET/POST` | `/portal/admin/users/{id}/edit` | Edit user (name, active, **admin role**, group memberships) |
| `POST` | `/portal/admin/users/{id}/delete` | Delete user |
| `POST` | `/portal/admin/users/{id}/reset-password` | Admin password reset (no current-password check; revokes existing sessions) |
| `POST` | `/portal/admin/users/{id}/clear-mfa` | Remove the user's TOTP and every WebAuthn credential |
| `GET` | `/portal/admin/groups` | List groups (roles) |
| `GET/POST` | `/portal/admin/groups/new` | Create group + assign members |
| `GET/POST` | `/portal/admin/groups/{id}/edit` | Edit group display name + membership |
| `POST` | `/portal/admin/groups/{id}/delete` | Delete group (members are not deleted) |
| `GET` | `/portal/admin/clients` | List OAuth clients |
| `GET/POST` | `/portal/admin/clients/new` | Create OAuth client |
| `GET/POST` | `/portal/admin/clients/{id}/edit` | Edit client |
| `POST` | `/portal/admin/clients/{id}/delete` | Delete client |
| `POST` | `/portal/admin/clients/{id}/rotate-secret` | Rotate client secret |
| `GET` | `/portal/apps` | Redirects to `/portal` (the launcher merged into the home page; kept for one transition cycle) |
| `GET` | `/portal/aws` | Redirects to `/portal` (legacy, kept for one transition cycle) |
| `POST` | `/portal/aws/console` | Assume the requested AWS role and redirect to AWS Console |
| `GET` | `/portal/aws/refresh` | AWS-Issuer URL: silently re-federates when the console session expires |
| `GET` | `/portal/admin/aws` | Admin: AWS accounts, roles, group→role assignments |
| `POST` | `/portal/admin/aws/accounts/new` | Register an AWS account |
| `POST` | `/portal/admin/aws/accounts/{id}/delete` | Delete (cascades to roles + assignments) |
| `POST` | `/portal/admin/aws/roles/new` | Register an assumable role |
| `POST` | `/portal/admin/aws/roles/{id}/delete` | Delete |
| `POST` | `/portal/admin/aws/assignments/new` | Add a group → role assignment |
| `POST` | `/portal/admin/aws/assignments/{id}/delete` | Delete |
| `GET` | `/portal/admin/integrations` | List app integrations (Vault SCIM, AWS IAM, …) |
| `GET/POST` | `/portal/admin/integrations/new` | Add a new integration |
| `GET/POST` | `/portal/admin/integrations/{id}/edit` | Edit integration; rotate token |
| `POST` | `/portal/admin/integrations/{id}/delete` | Remove integration |
| `POST` | `/portal/admin/integrations/{id}/test` | Probe SCIM ServiceProviderConfig using the integration's auth mode |
| `GET` | `/portal/admin/audit` | Live audit-log stream page (last 100 + tail via SSE) |
| `GET` | `/portal/admin/audit/sse` | Server-Sent-Events backing endpoint for the audit page; honours `Last-Event-ID` for resume |

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

## Application Portal

The portal home page (`/portal`) opens with the user-facing tile grid that aggregates every app the signed-in user can launch — OAuth2 clients (Vault, GitHub-compatible apps, internal apps) and AWS federation roles, all in one place — followed by a compact account summary. It replaces the earlier separate `/portal/apps` page and the AWS-only `/portal/aws` page; both URLs now redirect here.

### Making an OAuth client visible

OAuth2 clients are invisible by default — appropriate for machine clients (CI deploy keys, service accounts) and SaaS apps that initiate their own SSO from outside. To surface a client as a launchable tile, edit it at `/portal/admin/clients/{id}/edit` and fill in the **Portal visibility** section:

- **Show as tile on the portal home** — enables the tile.
- **Launch URL** — where the click navigates. Use the **RP's** initiate-login endpoint (e.g. `https://vault.example.com/ui/vault/auth/oidc`), not auth's `/authorize` — the RP needs to bootstrap its own state/nonce for the code flow.
- **Brand color / Icon URL** — optional cosmetics for the tile card.
- **Visible to everyone** — shows the tile to every authenticated user. Use for org-wide tools (status page, wiki).
- **Visible to SCIM groups** — when "visible to everyone" is off, the tile renders only for members of any checked group. Mirrors the AWS-role assignment model.

### Visibility resolution

The home-page launcher runs one DB query per source:

```
ListPortalClientsForUser(user)  →  OAuth clients where show_in_portal AND
                                    (visible_to_all OR user ∈ any linked group)

ListAWSRolesForUser(user)       →  AWS roles where user ∈ any group assigned
                                    to the role (aws_role_assignments)
```

Results are merged into a single tile grid and rendered. OIDC tiles produce plain `<a href="LaunchURL">` links; AWS tiles produce a form-POST to `/portal/aws/console`, which performs the existing `AssumeRoleWithWebIdentity` + `getSigninToken` dance.

### What this is not

- **Not an entitlement grant.** Showing a tile makes the launch URL discoverable; the RP still decides what the user can do after they land. OIDC scopes, role mappings, ABAC conditions — all still apply at the target app.
- **Not a redirect-through-auth gate.** Tiles for OIDC apps are normal hyperlinks the browser navigates to directly. Auth doesn't proxy launches, so the open-redirect concern that would apply to a `/portal/launch?to=…` shape doesn't exist here.

## AWS OIDC Federation (Console SSO without IAM users)

Federation is the recommended path for AWS Console + CLI access. Auth's portal acts as the single front door: users see role tiles, click a tile, land in the AWS Console with short-lived STS credentials. No IAM users are created, no long-lived AWS keys exist anywhere.

### Architecture in one paragraph

Auth publishes `/.well-known/openid-configuration` and `/.well-known/jwks.json`; AWS verifies signed id_tokens against the public JWKS. The portal handler at `/portal/aws/console` exchanges a freshly-minted federation id_token for STS credentials via `sts:AssumeRoleWithWebIdentity` (unauthenticated — the JWT is the auth), then trades those credentials for a console `SigninToken` at `signin.aws.amazon.com/federation`, then 302s the browser into the console. **Auth needs no AWS credentials for this flow.**

### Setup (per AWS account)

1. **Set the federation audience** in auth's environment. One value per IdP — typically scoped per AWS account so a JWT minted for one account can't be replayed against another:
   ```
   AUTHD_AWS_AUDIENCE=tokyo3-aws-prod
   ```
   Restart authd for the change to take effect. With this unset, the `/portal/aws` tile page and `/aws/credentials` endpoint return clear "federation_disabled" errors instead of silently dropping requests.

2. **Register the OIDC provider** (once per AWS account, scriptable via Terraform). Use the audience value from step 1 as `--client-id-list`:
   ```bash
   aws iam create-open-id-connect-provider \
     --url https://id.example.com \
     --client-id-list tokyo3-aws-prod
   # Thumbprint auto-discovered since Nov 2023; pass --thumbprint-list only if pinning.
   ```

3. **Create one role per persona** (e.g. `PlatformAdmin`, `BackendReadOnly`). Trust policies share the same audience but discriminate by `aws:RequestTag/team` — the per-role gate moves from the `aud` claim to the session-tag claim:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "Federated": "arn:aws:iam::ACCOUNT:oidc-provider/id.example.com" },
       "Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"],
       "Condition": {
         "StringEquals": {
           "id.example.com:aud": "tokyo3-aws-prod",
           "aws:RequestTag/team": "platform"
         }
       }
     }]
   }
   ```
   `aws:RequestTag/team` evaluates the team value being requested in the JWT's `https://aws.amazon.com/tags` claim — auth sets it server-side from the SCIM group that actually authorized this assumption (the alphabetically-first group that contains the user *and* is mapped to the requested role via `aws_role_assignments`), so users can't forge a different team. See `docs/integration-guide.md` Part 3 for the full ABAC pattern catalogue (per-user S3 prefix, team-scoped KMS, etc.).

4. **Configure auth** at `/portal/admin/aws`:
   - Add each AWS account: account ID, alias, OIDC provider ARN.
   - Add each role: ARN, slug (URL/CLI-safe identifier — e.g. `platform-prod`), display name, optional step-up MFA flag, session TTL.
   - Add SCIM-group → role assignments mapping group membership to assumable roles.

5. **Users log in** at `/portal`, click an AWS tile, land in the AWS Console. Roles flagged `require_step_up_mfa` interpose a fresh MFA challenge (`/portal/step-up`) when the session's last MFA is older than `AUTHD_STEP_UP_MFA_TTL` (default 5m); the user re-verifies and the assume continues without a second click.

### Revocation (optional but recommended)

Without revocation, STS sessions for a deactivated user keep working until natural expiry (≤role TTL, default 1h). To kill them in ≤30s, enable the revocation provisioner:

1. Attach a machine IAM role to whatever compute hosts authd (EC2 instance profile, ECS task role, EKS IRSA, IAM Roles Anywhere on-prem). **No static AWS keys.** Scoped policy:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy"],
       "Resource": ["arn:aws:iam::ACCOUNT:role/<role-name-pattern>"]
     }]
   }
   ```

2. Add an `aws_federation` integration row at `/portal/admin/integrations/new`. The provisioner picks up credentials transparently via the SDK's default chain — there's no token field to fill.

3. On deactivation, the provisioner adds the user's UUID to each federation role's `AuthRevokedUsers` inline policy:
   ```json
   {
     "Effect": "Deny",
     "Action": ["*"],
     "Resource": ["*"],
     "Condition": { "StringEquals": { "aws:PrincipalTag/sub": ["<deactivated-uuid>"] } }
   }
   ```
   AWS evaluates this on every API call — sessions tagged with the deactivated user's `sub` get `AccessDenied` on their next request (~30s policy propagation).

4. A daily reaper (`AUTHD_AWSFED_REAP_INTERVAL`, default 6h) trims revocation entries past the role's `MaxSessionDuration` — by then every session blocked by the Deny has expired naturally. Keeps the inline policy from growing forever.

### CloudTrail correlation

Every console-assumed session lands in CloudTrail with:
- `userIdentity.sessionContext.webIdFederationData.federatedProvider` = your issuer URL
- `userIdentity.sessionContext.webIdFederationData.attributes.sub` = auth user UUID
- `userIdentity.principalId` includes the `RoleSessionName` auth set, like `<email-local>-<uuid-prefix>-<unix>`

Cross-reference `sub` with auth's audit stream (action `aws.console.assumed`) for the complete picture.

### CLI access via `auth-aws-creds`

The browser flow handles AWS Console access. For CLI / SDK access, install the bundled helper:

```bash
go install github.com/abagile/tokyo3-auth/cmd/auth-aws-creds@latest
```

This ships from the same repo as `authd` but is a separate `main` package — `go install` pulls only the helper's transitive imports (no DB driver, no AWS SDK, no audit pipeline). Distributing prebuilt binaries works the same way; the standalone binary lives in `cmd/auth-aws-creds/`.

**One-time setup** (creates an OAuth public client in auth via `/portal/admin/clients/new` — public + PKCE, no client secret needed):

```bash
auth-aws-creds login --issuer https://id.example.com --client-id tokyo3-cli
# Opens browser, completes OIDC code flow on a loopback port, caches the refresh token.
```

Register the public client with **`http://127.0.0.1/callback`** (or `http://localhost/callback`) as a redirect URI. Auth applies RFC 8252 §7.3 loopback-aware matching, so the port the CLI picks at runtime (kernel-assigned by default, or `--port N` if you want to pin) is ignored — no per-port pre-registration needed. Same client_id works for both `auth-aws-creds` and `auth-ssh-creds`.

**Headless login** (no local browser — CI host, jump box, Docker exec session): add `--device` for the RFC 8628 device authorization grant. The CLI prints a verification URL + short code; complete the browser step on any device (phone, another laptop), and the CLI polls for the result.

```bash
auth-aws-creds login --issuer https://id.example.com --client-id tokyo3-cli --device
# Visit this URL to approve sign-in:
#    https://id.example.com/device?user_code=ABCD-WXYZ
# Or open https://id.example.com/device and enter ABCD-WXYZ
# Waiting for approval…
```

The OAuth client must have `allow_device_grant` set under `/portal/admin/clients/{id}/edit` for this to work — off by default to keep the device grant surface narrow. After login completes, `auth-aws-creds get` behaves identically regardless of which login flow you used.

**Configure each AWS profile to invoke the helper** as its credential source. The `role` flag matches the slug an admin set under `/portal/admin/aws/roles`:

```ini
# ~/.aws/config
[profile platform-prod]
credential_process = auth-aws-creds get --role platform-prod
region = us-east-1

[profile backend-dev]
credential_process = auth-aws-creds get --role backend-dev
region = us-east-1
```

The deprecated `--audience` flag is still accepted as an alias for `--role` to ease migration from 0.x configurations; it will be removed in a future release.

After that, `aws --profile platform-prod s3 ls` (or any boto3 / SDK invocation) silently:
1. Reads the cached STS credentials if still valid (skew = 60s).
2. Otherwise refreshes the OAuth access token via the cached refresh token (no browser).
3. Calls auth's `/aws/credentials` endpoint to obtain fresh STS credentials.
4. Caches the response and emits it as `credential_process` JSON on stdout.

A full browser-based re-login is only required when the refresh token expires (matches the OAuth client's refresh-token lifetime auth was configured with). `auth-aws-creds logout` clears the local cache.

**Cache layout** under `${XDG_CONFIG_HOME:-~/.config}/auth-sso/` (shared across every `auth-*-creds` helper, so one `login` serves all of them):

```
auth-sso/
├── config.json              ← issuer + client_id (non-secret, 0600)
├── tokens.json              ← OAuth access + refresh + id tokens (0600)
└── aws-creds/
    └── sts/<slug>.json      ← STS session credentials per role (0600)
```

> **Upgrading from a previous version that used `~/.config/auth-aws-creds/`?** Just run `auth-aws-creds login` once — the helper writes to the new location and ignores the old cache. You can `rm -rf ~/.config/auth-aws-creds` at your leisure.

**Programmatic endpoint**: the helper talks to `POST /aws/credentials` (bearer-auth, form body `role=<slug>`; `audience=<slug>` accepted as a deprecated alias). The response shape matches AWS CLI v2's `credential_process` JSON so a passthrough helper requires no marshalling.

## AWS IAM Users (legacy)

> **Deprecated for human access.** Use [AWS OIDC Federation](#aws-oidc-federation-console-sso-without-iam-users) above for console and CLI access. This section covers the older `aws_iam` provisioner that creates an IAM user per workforce member; keep it around for the narrow set of cases below, not as the default human-access path.

The `aws_iam` provisioner creates one IAM user per active auth user, tags them `ManagedBy=tokyo3-auth`, syncs SCIM-group → IAM-group memberships, and revokes access keys + group memberships on deactivation. It does **not** set a console password or generate access keys — those are operator-controlled lifecycle events outside auth's scope.

### When to enable

Only when you have a concrete dependency on a stable per-user IAM ARN:

- **CodeCommit Git credentials** — generated per IAM user via `iam:CreateServiceSpecificCredential` or `iam:UploadSSHPublicKey`. No federated equivalent exists. (AWS stopped accepting new CodeCommit customers in 2024; existing setups may still depend on this.)
- **SES SMTP credentials** — derived from an IAM user's access keys; SES's SMTP endpoint does not accept STS sessions. The SES *API* works fine with federated credentials, so this only matters when you're stuck on SMTP.
- **Resource policies that hardcode** `arn:aws:iam::ACCOUNT:user/<name>` as `Principal`. Greenfield environments don't have these; long-running AWS accounts often do. Audit with: `grep -rE 'arn:aws:iam::[0-9]+:user/' <terraform-state>`.
- **Third-party SaaS that only documents IAM user setup** for its AWS integration. Almost all support role-based access today; check the vendor's "advanced" / "production" docs before assuming IAM users are required.

For everything else — and especially for human workforce access — use federation. Federation gives you short-lived STS credentials, no per-user IAM rows, no long-lived keys, no `~/.aws/credentials` to leak.

### Setup

Add an `aws_iam` integration at `/portal/admin/integrations/new` (the admin form shows a deprecation banner with the same guidance as this section). The integration's `Group mapping` field maps SCIM group display names to IAM group names — when a user is added to a SCIM group, they're added to the corresponding IAM group automatically.

Credentials come from the AWS SDK default credential chain on the host running authd. Use a machine IAM role (EC2 instance profile, ECS task role, EKS IRSA, IAM Roles Anywhere); avoid static `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in production. The role needs: `iam:CreateUser`, `iam:TagUser`, `iam:DeleteUser`, `iam:CreateGroup`, `iam:AddUserToGroup`, `iam:RemoveUserFromGroup`, `iam:ListGroupsForUser`, `iam:ListAccessKeys`, `iam:DeleteAccessKey`.

### What the provisioner does NOT do

To set realistic expectations:

- **No console password** is set — `iam:CreateLoginProfile` is never called. Use `aws iam create-login-profile` out-of-band after provisioning if console access is desired.
- **No access keys** are minted — `iam:CreateAccessKey` is never called. Operators mint keys for the specific service integrations that need them.
- **No MFA enrollment** — IAM MFA is independent of auth's MFA.
- **Username collision risk**: usernames are derived as the email's local part (`alice@example.com` → `alice`). Two users with the same local part collide; auth logs the conflict but doesn't surface it elsewhere.

These omissions are deliberate — credentials are policy decisions, not provisioning decisions — but they mean the IAM provisioner is not a "create a fully-usable IAM user" feature. Pair it with whatever credential-issuance tooling your org uses.

## SSH access via `auth-ssh-creds`

`auth-ssh-creds` exchanges an SSO ID token (issued by auth) for a
short-lived SSH user certificate via certd's `/api/v1/ssh/sign-user`
endpoint, then writes the cert + private key next to each other so
`ssh -i` picks them up directly.

The binary **lives in the [tokyo3-ca](https://github.com/abagile/tokyo3-ca)
repo**, not here, because the wire shape it tracks is certd's
sign-user contract — when that contract evolves (TTL caps, principals
validation, key types, key_id derivation), the helper that POSTs to
it should land in the same review. SSO via auth is the prerequisite,
not the API surface the helper has to stay in sync with.

```bash
go install github.com/abagile/tokyo3-ca/cmd/auth-ssh-creds@latest
```

The helper shares the SSO cache at `~/.config/auth-sso/` with
`auth-aws-creds`, so a single `auth-aws-creds login` (or
`auth-ssh-creds login`) populates the tokens for both. Re-use the same
`tokyo3-cli` (or whatever you named it) public client registration —
no separate auth-side setup needed beyond the federated audience your
certd already validates.

Full usage docs (flag reference, cache layout, ssh_config snippet
emission via `--proxy-jump`, Docker image) live in the
[tokyo3-ca README](https://github.com/abagile/tokyo3-ca#cli-access-via-auth-ssh-creds).

**How the bearer token reaches certd**: `auth-ssh-creds` sends
`Authorization: Bearer <id_token>` to certd's `/api/v1/ssh/sign-user`
endpoint. certd validates the token against auth's JWKS
(`<issuer>/.well-known/jwks.json`) — no certd → auth callback needed;
the client carries the token end-to-end. JWKS caching means a
transient auth restart doesn't break cert issuance.

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
AUTHD_SCIM_MTLS_CERT=/run/secrets/auth-outbound.crt
AUTHD_SCIM_MTLS_KEY=/run/secrets/auth-outbound.key
AUTHD_SCIM_MTLS_CA=/run/secrets/downstream-ca.crt   # optional; falls back to system roots
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

**Legacy env vars**: `AUTHD_VAULT_SCIM_ENABLED`/`URL`/`TOKEN`/`TIMEOUT` are deprecated. On the first boot after upgrading, if `app_integrations` is empty and `AUTHD_VAULT_SCIM_ENABLED=true`, authd auto-imports the env vars into a row named `vault` and logs a deprecation warning. Subsequent boots ignore the env vars entirely — manage the row via the portal.

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
| 10.2.1 | All auth events, failures, and privilege changes journalled to NATS JetStream (`auth.audit.events`); fail-closed publish refuses the request on journal outage |

Evidence for each control is available in the `auth_audit` JetStream stream (`authd audit query`, or the `/portal/admin/audit` live-tail page) and the policy engine rule set in `internal/policy/pci.go`.

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

### Running locally

The development rig runs entirely in Docker:

```bash
make docker-up
# or, after `cd ../ca && make docker-up`:
make docker-up-mesh
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
