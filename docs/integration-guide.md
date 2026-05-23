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
AUTH_SCIM_MTLS_CERT=/run/secrets/auth-outbound.crt
AUTH_SCIM_MTLS_KEY=/run/secrets/auth-outbound.key
AUTH_SCIM_MTLS_CA=/run/secrets/downstream-ca.crt    # optional; empty = system roots
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
- Authentication: `Bearer token` (paste the value the target issued) **or** `mTLS (client cert)` (uses the shared `AUTH_SCIM_*` env vars; the target must allow-list auth's CA + SAN/CN)

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

## Part 3 — AWS console federation (OIDC + ABAC, no IAM users)

This is the recommended path for human access to AWS. Users log into auth, click a role tile, and land in the AWS Console with short-lived STS credentials. No IAM users are created; no long-lived AWS keys exist anywhere. Auth itself needs **no AWS credentials** for the federation flow — AWS verifies the signed id_token against auth's public JWKS, and the STS call is an unauthenticated POST whose body carries the JWT.

The runbook for OIDC provider registration, role catalog setup, and the optional revocation provisioner lives in the [README's "AWS OIDC Federation" section](../README.md#aws-oidc-federation-console-sso-without-iam-users). What follows below is the layer that gets the most operational mileage: **what session tags auth injects, and what authorization patterns those tags unlock on the AWS side.**

### Session tags auth injects

Every JWT minted by auth's federation handler carries a `https://aws.amazon.com/tags` claim (a special claim name AWS recognises) containing:

```json
{
  "principal_tags": {
    "sub":   ["<auth user UUID>"],
    "email": ["alice@example.com"],
    "team":  ["<first SCIM group display name>"]
  },
  "transitive_tag_keys": ["email", "sub", "team"]
}
```

`sub` is always emitted. `email` is emitted when the user has one. `team` is emitted from the user's first SCIM group (alphabetical order; rest of the groups go into the informational `groups` claim but are not session-tagged). All three are marked **transitive**, meaning they persist through any subsequent `sts:AssumeRole` chain calls.

AWS reads this claim during `AssumeRoleWithWebIdentity` and surfaces each tag at two stages:

- **At trust-policy evaluation time** (before the session exists) the tag values are available as `aws:RequestTag/<key>`. Role trust policies condition on `aws:RequestTag/team` to decide who can assume each role — this is the per-role discriminator now that audience is a single shared value (sourced from `AUTH_AWS_AUDIENCE`).
- **For every subsequent API call** under the resulting STS session the same values surface as `aws:PrincipalTag/<key>`. Resource policies, permission policies, SCPs, and the awsfed revocation Deny all key on this form.

**Prerequisite**: each federation role's trust policy must include `sts:TagSession` in the Action list:

```json
"Action": ["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]
```

Omit this and AWS refuses the AssumeRole call when the JWT carries tags.

### ABAC pattern catalogue

Patterns operators apply on the AWS side, **owned and edited by AWS account operators** (typically via Terraform). Auth does not write these — auth's role is to deliver the session tags accurately. Once delivered, they're load-bearing primitives for every authz decision below.

#### Pattern 1 — Per-user S3 prefix isolation

The most common ask: each workforce member gets their own scratch prefix in a shared bucket.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PerUserPrefix",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/PlatformReadOnly" },
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::shared-bucket/${aws:PrincipalTag/sub}/*"
  }]
}
```

`${aws:PrincipalTag/sub}` substitutes Alice's UUID for Alice, Bob's UUID for Bob. One statement, per-user isolation, scales to any number of users without policy edits. Without session tags this required either one IAM user per human (legacy) or one Allow statement per user (doesn't scale).

#### Pattern 2 — Team-scoped KMS access

Grant a team blanket Decrypt access to a key without naming individuals:

```json
{
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/DataAnalyst" },
  "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
  "Resource": "*",
  "Condition": {
    "StringEquals": { "aws:PrincipalTag/team": "data" }
  }
}
```

The role itself can be shared across teams; the KMS key policy filters which team sessions are accepted. Membership rotation is auth-side (move someone in/out of the `data` SCIM group); AWS-side policies don't change.

#### Pattern 3 — Object-tag matching for object ownership

Each S3 object's `owner` tag must equal the requester's `sub` tag. Lets you grant per-object access without per-user policies:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "arn:aws:s3:::user-uploads/*",
  "Condition": {
    "StringEquals": { "s3:ExistingObjectTag/owner": "${aws:PrincipalTag/sub}" }
  }
}
```

Combine with a separate write policy that requires `s3:RequestObjectTag/owner = ${aws:PrincipalTag/sub}` so users can only tag objects with their own UUID at upload time. Result: every object is owned by whoever uploaded it, readable only by its owner, without per-user policy management.

#### Pattern 4 — Self-revocation via the awsfed provisioner

The `internal/provision/awsfed` package adds deactivated users to each federation role's `AuthRevokedUsers` inline policy:

```json
{
  "Sid": "AuthRevokedUsers",
  "Effect": "Deny",
  "Action": ["*"],
  "Resource": ["*"],
  "Condition": {
    "StringEquals": {
      "aws:PrincipalTag/sub": ["alice-uuid", "bob-uuid"]
    }
  }
}
```

Sessions whose `sub` tag matches any UUID in the list get `AccessDenied` on every API call (~30s policy propagation). Auth manages the list automatically on `OpDeactivate`. A reaper trims entries past the role's `MaxSessionDuration` since by then the protected sessions have already expired. This is the **session revocation** primitive that closes the deactivation latency gap that pure expiry alone leaves open.

#### Pattern 5 — Cross-account boundary enforcement

If a role is shared across accounts and you want to ensure session tags weren't forged in a chained AssumeRole, require the originating IdP:

```json
{
  "Effect": "Allow",
  "Action": "s3:GetObject",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:FederatedProvider": "arn:aws:iam::ACCOUNT:oidc-provider/id.example.com"
    }
  }
}
```

`aws:FederatedProvider` is set by STS during web-identity federation and survives role chaining. Combining it with `aws:PrincipalTag/*` guarantees the tags came from auth, not from a downstream role that an attacker manipulated.

### Designing the role catalogue

Two architectural decisions land in this area; both are worth being deliberate about:

**Role granularity.** Build per-persona roles (`PlatformAdmin`, `BackendDev`, `DataAnalyst`) and lean on ABAC for per-user scoping inside them. Per-user roles (one per human) don't scale past a couple hundred users. Each role gets a unique trust-policy condition on `aws:RequestTag/team` (or another tag key) — that condition is what distinguishes "who can assume this role" rather than a per-role audience.

**Audience model.** The federation handler emits a single audience value on every JWT, sourced from the `AUTH_AWS_AUDIENCE` env var (typically one value per AWS account — `tokyo3-aws-prod`, `tokyo3-aws-staging`, `tokyo3-aws-dev`). This value is registered once on each account's IAM OIDC provider and shared across every role in that account. Per-role gating moves entirely into `aws:RequestTag/<key>` conditions in trust policies — no role-specific audience values to keep in sync. Audience values are not secrets; they appear in CloudTrail under `webIdFederationData.attributes.aud`.

**Role slug.** The `slug` field on each role (`platform-prod`, `backend-dev`) is the URL/CLI-safe identifier users supply in their `~/.aws/config` (`credential_process = auth-aws-creds get --role <slug>`) and the `role` form field on `POST /aws/credentials`. Auth validates slugs against `[a-z0-9][a-z0-9_-]{0,62}` at admin form time. The display name (`Platform: prod`) is the human-friendly label rendered on the user tile page.

### Audit trail

Every federation event lands in auth's JetStream audit stream:

- `aws.console.assumed` on success, with `role_arn`, `role_slug`, `audience` (server-global from `AUTH_AWS_AUDIENCE`), `role_session_name`, `step_up`, `mfa_authenticated` in metadata
- `aws.console.assume.failed` with `reason` (`not_assigned`, `step_up_required`, `sts_error`, `signin_token_error`)
- `aws.federation.revoked` when the provisioner adds a user to a role's revocation list
- `aws.federation.revoke.reaped` when the reaper prunes expired entries

AWS-side, every API call carries the federated identity through CloudTrail's `userIdentity`:
- `webIdFederationData.federatedProvider` = your issuer URL
- `webIdFederationData.attributes.sub` = auth user UUID
- `principalId` includes `RoleSessionName` = `<email-local>-<uuid-prefix>-<unix>`

Join auth's audit on `user_id` with CloudTrail on `sub` for the complete story (auth side tells you "who triggered the role assumption"; CloudTrail tells you "what AWS actions ran under that session").

### What's deliberately not in this design

- **No IAM users created for workforce members.** Federation is identity-less in AWS — sessions are minted on demand, no per-user IAM rows.

  The `iam` provisioner (`internal/provision/iam`, labelled "AWS IAM Users (legacy)" in the admin form) is kept as a deliberate escape hatch for environments where IAM users are *actually* required:
  - **CodeCommit Git credentials** (`iam:CreateServiceSpecificCredential`, `iam:UploadSSHPublicKey`) — no federation alternative
  - **SES SMTP credentials** — derived from IAM access keys; SES's SMTP endpoint doesn't accept STS sessions (the SES *API* does)
  - **Resource policies that hardcode `arn:aws:iam::ACCOUNT:user/<name>` as Principal** — common in long-running AWS accounts; rare in greenfield
  - **Third-party SaaS that only documents IAM-user setup** — check the vendor's role-based integration docs before assuming this applies

  Greenfield deployments should not enable the `iam` provisioner. The admin form surfaces a deprecation banner explaining the same — federation is the human-access path, and `aws_iam` is the legacy compatibility hatch.
- **No Identity Center.** Direct OIDC federation against auth is the architecturally simpler answer for ≤5 AWS accounts. Identity Center pays off at higher account counts and unlocks Trusted Identity Propagation for analytics services (QuickSight rows, S3 Access Grants, Redshift query authorization) — but requires SAML support in the IdP, which auth doesn't have today.
- **CLI credential helper lives at `cmd/auth-aws-creds/`** in this same repo (not a separate project). Install with `go install github.com/abagile/tokyo3-auth/cmd/auth-aws-creds@latest`; users wire it via `credential_process` in `~/.aws/config`. The helper depends only on the standard library and `internal/awsclaims` — no DB or AWS SDK in its import graph, so installing it doesn't drag in server dependencies.

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
  - *mTLS mode:* the cert/key pointed at by `AUTH_SCIM_MTLS_CERT/KEY` is hot-reloaded automatically — replace the file on disk (tbot, cert-manager, SPIFFE) and the next SCIM request picks it up. No process restart, no portal save.
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
- `auth/internal/provision/awsfed/awsfed.go` — AWS OIDC federation revocation provisioner (session-tag Deny + reaper)
- `auth/internal/api/web_portal_aws.go` — user-facing federation handler (`/portal/aws`, `/portal/aws/console`, `/portal/aws/refresh`)
- `auth/internal/api/web_portal_aws_admin.go` — admin UI for the federation catalogue (accounts, roles, group→role assignments)
- `auth/internal/api/aws_credentials.go` — programmatic `/aws/credentials` endpoint consumed by `auth-aws-creds`
- `auth/internal/awsclaims/claims.go` — shared JWT claim constants (`PrincipalTagsClaim`, `PrincipalTagsValue`)
- `auth/internal/jwt/signer.go` — `MintFederationToken`, session-tag claim shaping
- `auth/cmd/auth-aws-creds/main.go` — CLI credential helper for boto3 `credential_process`
- `auth/internal/api/admin.go`, `web_sso.go`, `web_portal.go`, `web_portal_groups.go` — native-path fan-out call sites
- `auth/cmd/authd/main.go` — `buildProvisioner` (auth-mode dispatch), `outboundTLSFromEnv`, `awsFedReapInterval`, `admin sync` subcommand
- `vault/docs/oidc-sso-design.md` — vault-side protocol details, SCIM filter subset, "tokyo3-auth as IdP" appendix
