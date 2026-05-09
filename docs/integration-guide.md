# Integration guide

How to bring up the auth ↔ vault bridge, and how to extend the same pattern to any future downstream app.

## Architecture in one paragraph

Auth is the source of truth for identity. Two channels carry that identity outward:

- **OIDC** — downstream apps log users in by redirecting to auth's `/authorize`. Each app is an entry in auth's `clients` table.
- **Provisioning** — auth pushes user/group lifecycle events (create / update / deactivate / delete) to downstream systems through `provision.Set` whenever an authoritative mutation happens (inbound SCIM, admin API, self-registration, portal admin). Each downstream is a `provision.Provisioner` implementation. The built-in implementations are `iam` (AWS IAM) and `scim` (SCIM 2.0 over bearer auth, used for vault).

The two channels are independent. An app can use either, both, or neither.

```
                       ┌──────────┐
                       │   auth   │  source of truth
                       └────┬─────┘
                            │
          ┌─────────────────┼─────────────────┐
          │ OIDC            │ Provisioner.Set │
          ▼                 ▼                 ▼
       ┌─────┐           ┌─────┐           ┌─────┐
       │ app │           │ app │           │ app │
       └─────┘           └─────┘           └─────┘
       login only        provision only    both (e.g. vault)
```

---

## Part 1 — Bring up the auth ↔ vault bridge

Step 1 registers vault for OIDC SSO. Step 2 wires the SCIM provisioning channel — pick *one* of the two auth modes (bearer or mTLS; they're mutually exclusive per integration). Step 3 backfills existing users. Step 4 is an optional policy step. Step 5 verifies the result.

### 1. Register vault as an OAuth2 client in auth

```sh
curl -X POST -H "Authorization: Bearer $AUTH_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     "$AUTH_URL/admin/clients" \
     -d '{
       "name": "vault",
       "redirect_uris": ["https://vault.example.com/api/v1/auth/oidc/callback"],
       "scopes": ["openid","email","profile","offline_access"],
       "public": false
     }'
# Capture client_id + client_secret (secret shown ONCE).
```

Configure vault server env and restart:

```sh
VAULT_OIDC_ISSUER=https://auth.example.com
VAULT_OIDC_CLIENT_ID=<from above>
VAULT_OIDC_CLIENT_SECRET=<from above>
VAULT_OIDC_REDIRECT_URI=https://vault.example.com/api/v1/auth/oidc/callback
VAULT_OIDC_ENFORCE=true     # optional — disables local /auth/login + /auth/signup
```

### 2. Wire the SCIM provisioning channel — pick one auth mode

#### Option A — Bearer token

Mint a SCIM token on vault:

```sh
curl -X POST -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     "$VAULT_URL/api/v1/scim/tokens" \
     -d '{"description":"tokyo3-auth -> vault provisioner"}'
# Response includes "token" — shown ONCE. Stash it.
```

Add a Vault SCIM integration at `/portal/admin/integrations/new`:
- Provider: `scim`
- Authentication: **Bearer token**
- Base URL: `https://vault.example.com/scim/v2`
- Token: paste the value above

#### Option B — mTLS (no token bootstrap, cert infra required)

Configure vault to require client certs on `/scim/v2/*` and allow-list auth's CA + the SAN/CN that identifies authd. Then point auth at its outbound cert/key/CA via env vars (one shared identity for every mTLS integration; no per-row secrets):

```sh
AUTH_OUTBOUND_TLS_CERT=/run/secrets/auth-outbound.crt
AUTH_OUTBOUND_TLS_KEY=/run/secrets/auth-outbound.key
AUTH_OUTBOUND_TLS_CA=/run/secrets/downstream-ca.crt    # optional; empty = system roots
```

Restart auth. The cert file is hot-reloaded (mtime polled at most once per second across SCIM requests), so pair this with tbot, cert-manager, or SPIFFE for automatic rotation without restarts.

Add the integration at `/portal/admin/integrations/new`:
- Provider: `scim`
- Authentication: **mTLS (client cert)**
- Base URL: `https://vault.example.com/scim/v2`
  (The token field disappears in this mode.)

#### After either option

Click **Test** on the integration row to confirm authd can reach vault before sending real traffic.

### 3. Backfill existing users

```sh
authd admin sync --target=vault
# sync vault done: users N ok / 0 failed; groups M ok / 0 failed
```

Required only the first time the bridge is enabled, or after a downstream restore from backup. The provisioner only fires on *new* mutations — it has no startup hook that scans existing rows. Idempotent: safe to re-run.

### 4. (Optional) Pre-populate group → role mappings on vault

Vault's policy decisions live in `scim_group_roles`. Operator must define them once:

```sh
curl -X POST -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
     "$VAULT_URL/api/v1/scim/group-roles" \
     -d '{
       "scim_external_id": "<auth-group-uuid>",
       "display_name": "Engineering",
       "project_slug": "platform",
       "env_slug": "production",
       "role": "editor"
     }'
```

`scim_external_id` is the auth-side group UUID — copy it from `Admin → Groups → edit` in the auth portal, or from `GET /api/v1/admin/groups`. After this, when auth's "Engineering" group syncs over with members, vault auto-binds those users to `platform/production` with `editor`.

### 5. Smoke test

```sh
# OIDC SSO
vault login --oidc --server https://vault.example.com
vault projects list                             # any authenticated call confirms the token works

# SCIM round-trip — create a user in auth (portal or admin API), then:
curl -H "Authorization: Bearer $SCIM_TOKEN" \
     "$VAULT_URL/scim/v2/Users?filter=externalId%20eq%20%22<auth-user-uuid>%22" \
     | jq .totalResults                          # 1

# Deactivation — set active=false in auth, confirm vault tokens were revoked
```

---

## Part 2 — Adding a new downstream app

Three levels. Pick the lowest one that fits.

### Level A — same SCIM protocol, different downstream

If the target speaks SCIM 2.0 over bearer auth or mTLS (Okta-as-target, Azure-as-target, an internal app), no Go code changes are required — the existing `internal/provision/scim` client handles it. Add a row at `/portal/admin/integrations/new`:

- Provider: `scim`
- Name: any unique identifier (used as the `external_ids` cache key — don't rename a live integration)
- Base URL: the target's SCIM root
- Authentication: `Bearer token` (paste the value the target issued) **or** `mTLS (client cert)` (uses the shared `AUTH_OUTBOUND_TLS_*` env vars; the target must allow-list auth's CA + SAN/CN)

Backfill existing users with `authd admin sync --target=<name>`. The integration is then live for all subsequent mutations.

**Downstream compatibility checklist:**

| Capability | Required? | Why |
|---|---|---|
| `POST /Users` idempotent on userName/email | Strongly preferred | Self-heal falls through to POST after a 404 |
| `filter=externalId eq "..."` on `GET /Users` | Strongly preferred | Self-heal re-resolution path |
| `PATCH /Users/{id}` with `Replace` ops | Required | Active flag + name updates |
| `DELETE /Users/{id}` | Required | `OpDelete` |
| `GET /Groups?filter=displayName eq "..."` | Required if pushing groups | Group resolution |
| `PUT /Groups/{id}` with full `members[]` | Required if pushing groups | Membership replace |

If the target lacks filter, the cache still works for the happy path — but a stale-cache 404 falls through to `POST` and may create a duplicate (the target's POST idempotency saves you, or you live without self-heal).

### Level B — different protocol (write a new Provisioner)

Target uses a SCIM-like-but-different shape, a custom REST API, or a Slack-style webhook. Implement the interface:

```go
// internal/provision/<target>/<target>.go
package fooapp

type Provisioner struct { /* http client, base URL, token, etc. */ }

func (*Provisioner) Name() string { return "fooapp" }

func (p *Provisioner) User(ctx context.Context, op provision.Op, u *model.User, groups []string) error {
    switch op {
    case provision.OpCreate:     // POST to fooapp's create endpoint
    case provision.OpUpdate:     // PUT/PATCH
    case provision.OpDeactivate: // fooapp's "disable" semantics
    case provision.OpDelete:     // DELETE
    }
    return nil
}

func (p *Provisioner) Group(ctx context.Context, op provision.Op, g *model.SCIMGroup, members []*model.User) error {
    /* … */
}
```

Wire it into `cmd/authd/main.go`'s `buildProvisioner` switch alongside the existing `scim` and `aws_iam` cases, and add a new `AppIntegrationProvider*` constant in `internal/model/model.go`. The fan-out, all native-path hooks, and the `external_ids` cache work unchanged. Typical size: 150–300 LOC + tests.

### Level C — no provisioning API, OIDC-only

Some apps only support inbound SSO and have no programmatic provisioning. Two paths:

- **OIDC** — register the app as a client in auth (Part 1 step 1). Users are created on the app side via JIT-on-first-login (mirroring how vault's `jitProvision` works).
- **SAML** — auth doesn't speak SAML today. Either add SAML support to auth, or front with an OIDC↔SAML bridge (`saml2aws`-style).

No `Provisioner` impl needed. The trade-off: no proactive deactivation — when you disable a user in auth, the downstream app finds out only on the user's next login attempt (when SSO fails). For deprovisioning-sensitive apps (anything touching production), prefer Level A or B.

---

## Decision flowchart

```
Adding a new app
│
├─ Does it speak OIDC?
│  ├─ Yes → register as OAuth2 client in auth (Part 1 step 1). Done for SSO.
│  └─ No  → add SAML support to auth, or front with a bridge.
│
└─ Does it speak SCIM 2.0 (bearer or mTLS)?
   ├─ Yes  → Level A. Add a row in /portal/admin/integrations. No code changes.
   ├─ Like-SCIM → Level B. Implement provision.Provisioner. ~200 LOC.
   └─ None → Level C. Rely on JIT-on-SSO; no proactive deprovisioning.
```

---

## Operational notes

- **Credential rotation.**
  - *Bearer mode:* tokens are long-lived. Rotate via the downstream's token endpoint, then click **Replace token** on the integration's edit page. The new token is encrypted with the master KEK and the registry hot-reloads on save.
  - *mTLS mode:* the cert/key pointed at by `AUTH_OUTBOUND_TLS_CERT/KEY` is hot-reloaded automatically — replace the file on disk (tbot, cert-manager, SPIFFE) and the next SCIM request picks it up. No process restart, no portal save.
- **Failure mode.** Provisioner errors are logged and audited but never block the originating request. A failed downstream sync is recoverable via `authd admin sync --target=<name>`.
- **404 self-heal.** The SCIM client treats `external_ids` as a cache, not authority. On `404` from `PUT/PATCH/DELETE` it invalidates the cache and re-resolves via `filter=externalId eq`, then either retries or falls through to `POST` (idempotent on email).
- **Order of operations on first deploy.** Provision before SSO. If a user logs in via OIDC before they've been SCIM-provisioned, the downstream JIT-creates them with no `externalId` — which still works via email fallback, but later updates take an extra round trip until the cache is populated. Run `authd admin sync` first.
- **Audit trail.** Every provisioner call produces an audit entry on the auth side via the `Name()` field. Look for `target=<integration name>` in `audit_logs`.
- **mTLS identity binding.** When using mTLS, the downstream MUST verify both the CA chain *and* the cert's SAN/CN identifies authd specifically. CA chain alone leaks trust to every other service in the same trust domain. Pin a stable identity (CN, SPIFFE ID) — never the cert hash, since the cert rotates.

---

## Reference

- `auth/internal/provision/provision.go` — `Provisioner` interface + `Set` fan-out
- `auth/internal/provision/registry.go` — hot-reloading wrapper around `Set` (rebuilt on integration save)
- `auth/internal/provision/scim/client.go` — generic SCIM 2.0 outbound client (bearer + mTLS)
- `auth/internal/provision/iam/iam.go` — AWS IAM provisioner (reference impl for non-SCIM targets)
- `auth/internal/api/admin.go`, `web_sso.go`, `web_portal.go`, `web_portal_groups.go` — native-path fan-out call sites
- `auth/cmd/authd/main.go` — `buildProvisioner` (auth-mode dispatch), `outboundTLSFromEnv`, `admin sync` subcommand
- `auth/cmd/authd/main.go` — provisioner construction + `admin sync` subcommand
- `vault/docs/oidc-sso-design.md` — vault-side protocol details, SCIM filter subset, "tokyo3-auth as IdP" appendix
