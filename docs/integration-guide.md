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

Steps 1–2 are one-time HTTP calls. Steps 3–4 are env-var changes and a restart. Step 5 backfills existing users. Step 6 is an optional policy step. Step 7 verifies the result.

### 1. Mint a SCIM bearer token on vault

```sh
curl -X POST -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
     -H "Content-Type: application/json" \
     "$VAULT_URL/api/v1/scim/tokens" \
     -d '{"description":"tokyo3-auth -> vault provisioner"}'
# Response includes "token" — shown ONCE. Stash it.
```

### 2. Register vault as an OAuth2 client in auth

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

### 3. Configure vault server env

```sh
VAULT_OIDC_ISSUER=https://auth.example.com
VAULT_OIDC_CLIENT_ID=<from step 2>
VAULT_OIDC_CLIENT_SECRET=<from step 2>
VAULT_OIDC_REDIRECT_URI=https://vault.example.com/api/v1/auth/oidc/callback
VAULT_OIDC_ENFORCE=true     # optional — disables local /auth/login + /auth/signup
```

Restart vault.

### 4. Configure auth server env

```sh
AUTH_VAULT_SCIM_ENABLED=true
AUTH_VAULT_SCIM_URL=https://vault.example.com/scim/v2
AUTH_VAULT_SCIM_TOKEN=<from step 1>
AUTH_VAULT_SCIM_TIMEOUT=10s   # optional
```

Restart auth.

### 5. Backfill existing users

```sh
authd admin sync --target=vault
# sync vault done: users N ok / 0 failed; groups M ok / 0 failed
```

Required only the first time the bridge is enabled, or after a downstream restore from backup. The provisioner only fires on *new* mutations — it has no startup hook that scans existing rows. Idempotent: safe to re-run.

### 6. (Optional) Pre-populate group → role mappings on vault

Vault's policy decisions live in `scim_group_roles`. Operator must define them once:

```sh
curl -X POST -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
     "$VAULT_URL/api/v1/scim/group-roles" \
     -d '{
       "display_name": "Engineering",
       "project_slug": "platform",
       "env_slug": "production",
       "role": "editor"
     }'
```

After this, when auth's "Engineering" group syncs over with members, vault auto-binds those users to `platform/production` with `editor`.

### 7. Smoke test

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

If the target speaks SCIM 2.0 over bearer auth (Okta-as-target, Azure-as-target, an internal app), the existing `internal/provision/scim` client works as-is. Register a new instance in `cmd/authd/main.go`:

```go
if strings.EqualFold(os.Getenv("AUTH_FOOAPP_SCIM_ENABLED"), "true") {
    fooProv := scimprov.New(scimprov.Config{
        Provider: "fooapp",         // unique cache key in external_ids
        Name:     "fooapp-scim",    // appears in audit logs
        BaseURL:  os.Getenv("AUTH_FOOAPP_SCIM_URL"),
        Token:    os.Getenv("AUTH_FOOAPP_SCIM_TOKEN"),
        Store:    db,
        Log:      log,
    })
    provSet.Provisioners = append(provSet.Provisioners, fooProv)
}
```

Add `fooapp` to the switch in `runAdminSync` (or generalize the switch to look up by `Provisioner.Name()`).

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

Append it to `provSet.Provisioners` in `main.go`. The fan-out, all native-path hooks, and the `external_ids` cache work unchanged. Typical size: 150–300 LOC + tests.

### Level C — no provisioning API, OIDC-only

Some apps only support inbound SSO and have no programmatic provisioning. Two paths:

- **OIDC** — register the app as a client in auth (Part 1 step 2). Users are created on the app side via JIT-on-first-login (mirroring how vault's `jitProvision` works).
- **SAML** — auth doesn't speak SAML today. Either add SAML support to auth, or front with an OIDC↔SAML bridge (`saml2aws`-style).

No `Provisioner` impl needed. The trade-off: no proactive deactivation — when you disable a user in auth, the downstream app finds out only on the user's next login attempt (when SSO fails). For deprovisioning-sensitive apps (anything touching production), prefer Level A or B.

---

## Decision flowchart

```
Adding a new app
│
├─ Does it speak OIDC?
│  ├─ Yes → register as OAuth2 client in auth (Part 1 step 2). Done for SSO.
│  └─ No  → add SAML support to auth, or front with a bridge.
│
└─ Does it speak SCIM 2.0 + bearer?
   ├─ Yes  → Level A. Env vars + append to provSet. No new Go code.
   ├─ Like-SCIM → Level B. Implement provision.Provisioner. ~200 LOC.
   └─ None → Level C. Rely on JIT-on-SSO; no proactive deprovisioning.
```

---

## Operational notes

- **Token rotation.** `AUTH_VAULT_SCIM_TOKEN` and other downstream tokens are long-lived. Rotate via the downstream's token endpoint (`POST /api/v1/scim/tokens` for vault) and update the env. No restart-coordination needed beyond the usual config reload.
- **Failure mode.** Provisioner errors are logged and audited but never block the originating request. A failed downstream sync is recoverable via `authd admin sync --target=<name>`.
- **404 self-heal.** The SCIM client treats `external_ids` as a cache, not authority. On `404` from `PUT/PATCH/DELETE` it invalidates the cache and re-resolves via `filter=externalId eq`, then either retries or falls through to `POST` (idempotent on email).
- **Order of operations on first deploy.** Provision before SSO. If a user logs in via OIDC before they've been SCIM-provisioned, the downstream JIT-creates them with no `externalId` — which still works via email fallback, but later updates take an extra round trip until the cache is populated. Run `authd admin sync` first.
- **Audit trail.** Every provisioner call produces an audit entry on the auth side via the `Name()` field. Look for `target=vault-scim` (or whichever target name) in `audit_logs`.

---

## Reference

- `auth/internal/provision/provision.go` — `Provisioner` interface + `Set` fan-out
- `auth/internal/provision/scim/client.go` — generic SCIM 2.0 outbound client
- `auth/internal/provision/iam/iam.go` — AWS IAM provisioner (reference impl for non-SCIM targets)
- `auth/internal/api/scim.go`, `admin.go`, `web_sso.go`, `web_portal.go` — native-path fan-out call sites
- `auth/cmd/authd/main.go` — provisioner construction + `admin sync` subcommand
- `vault/docs/oidc-sso-design.md` — vault-side protocol details, SCIM filter subset, "tokyo3-auth as IdP" appendix
