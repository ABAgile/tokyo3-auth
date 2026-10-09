# Upgrade checklist

Work through this before deploying a build that includes migrations
`020` to `022`, or any later release. Items marked **breaking** can make
a previously working deployment fail at startup or reject requests that used
to succeed.

## 1. Before you deploy

- [ ] **Back up the database.** Migration `022` adds `auth_time` to `grants`
      and `sessions` and a `retired_refresh_tokens` table, `021` adds a column
      to `grants`, and `020` updates `app_integrations`. All are additive, but
      migrations run automatically on `authd serve` and `authd migrate`.
- [ ] **Run migrations with the admin DSN.** `AUTHD_ADMIN_DATABASE_URL`
      (falls back to `AUTHD_DATABASE_URL`). The runtime role stays DML-only.
- [ ] **Validate configuration on a staging copy first** (see §2). `authd serve`
      now refuses to start on a bad value and names every offending variable at
      once, so a dry start surfaces all problems in one pass.

## 2. Configuration changes (**breaking**)

`authd` now parses and validates its environment before it opens NATS, the
database, or any worker. Values that used to be silently ignored are now
startup errors:

| Variable | Old behaviour | New behaviour |
|----------|---------------|---------------|
| `AUTHD_ISSUER` | any non-empty string | must be an absolute `https`/`http` URL with a host and no query or fragment |
| `AUTHD_ADDR` | any string | must be `host:port` (e.g. `:8443`) |
| `AUTHD_ALLOW_REGISTRATION` | anything but `true` meant off | strict boolean; `yes`, `on`, … fail startup (`true`/`false`/`1`/`0` accepted) |
| `AUTHD_STEP_UP_MFA_TTL` | invalid value fell back to `5m` | invalid or negative value fails startup |
| `AUTHD_PROVISION_SYNC_INTERVAL`, `AUTHD_AWSFED_REAP_INTERVAL` | invalid value logged a warning and disabled the worker | invalid value fails startup; explicit `0` or a negative duration still disables it |
| `AUTHD_VAULT_SCIM_TIMEOUT`, `AUTHD_WEBAUTHN_ORIGINS` | not validated | malformed values fail startup |

New optional variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `AUTHD_AUTH_RATE_PER_MIN` | `20` | per-IP budget for interactive credential endpoints (including `/mfa/totp/enroll` and `/confirm`) |
| `AUTHD_TOKEN_RATE_PER_MIN` | `120` | per-IP budget for `/token`, `/revoke`, `/device_authorization`, `/aws/credentials` |
| `AUTHD_TRUSTED_PROXIES` | _(none)_ | extra CIDRs whose `X-Forwarded-For` is trusted |

- [ ] **Check your reverse proxy address.** `X-Forwarded-For` is trusted only
      when the connecting peer is loopback, RFC 1918 / `fc00::/7`, or listed in
      `AUTHD_TRUSTED_PROXIES`. If your proxy or load balancer connects from a
      **public** address and this is not set, every user appears to come from
      the proxy: they share one rate-limit bucket (expect `429`s under load)
      and audit records show the proxy's address.
- [ ] **Audit IP semantics changed.** The audit log's `ip` (and device-grant
      `approver_ip`) previously took the first `X-Forwarded-For` hop from any
      caller, which a client could forge. It now uses the same trusted-proxy
      logic as the rate limiter. Anything that parsed those fields expecting the
      old (spoofable) value will see the real client address instead.
- [ ] **Rate limits and shared egress IPs.** Relying-party backends that
      exchange codes for many users from one address share the `/token` budget
      (default 120/min). Raise `AUTHD_TOKEN_RATE_PER_MIN` if they throttle.
      Users behind a corporate NAT share the interactive budget
      (`AUTHD_AUTH_RATE_PER_MIN`, default 20/min).

## 3. OAuth client behaviour (**breaking**)

- [ ] **Scopes are enforced against client registration.** `/authorize` and
      `client_credentials` now reject any scope the client is not registered
      for: `/authorize` redirects with `error=invalid_scope`, `/token` returns
      `400 invalid_scope`. Previously unregistered scopes were silently
      granted. For each relying party (Vault, Wazuh/OpenSearch, custom apps),
      compare the scopes it requests with the client's registered scopes in
      `/portal/admin/clients` and add any that are missing (commonly `groups`,
      `profile`, `email`).
- [ ] **Admin API requires an active admin user.** A bearer token with the
      `admin` scope is no longer sufficient: its user must have the admin flag
      and be active. Scripts using a `client_credentials` token with the
      `admin` scope keep working only if that client is registered with the
      `admin` scope.
- [ ] **Refresh tokens rotate atomically.** A refresh issues a new access
      token that is now actually stored (previously the returned access token
      was rejected by `/userinfo`) and retires the old one.
- [ ] **Refresh-token replay revokes the session.** Presenting a refresh
      token that was already rotated away (RFC 9700 §4.14: the token was
      copied) returns `400 invalid_grant`, **deletes that session**, and
      records an `auth.token.refresh_reuse` audit event; the tokens the
      legitimate holder just received stop working too, so they must sign in
      again. Two concurrent refreshes with the same token count as a replay.
      Clients must serialise refreshes and persist the newest pair before
      using it, and must not blindly retry a refresh whose response they
      lost. The shared SSO helpers (`auth-aws-creds`, `auth-ssh-creds`)
      already take an advisory file lock on Unix; on other platforms
      concurrent helper invocations can trigger a revocation. Add an alert on
      `auth.token.refresh_reuse`: repeated events for one user suggest theft
      (or a misbehaving client).
- [ ] **Authorization codes are strictly single-use**, including under
      concurrent redemption.
- [ ] **`auth_time` is the real login time.** It was the moment the token was
      minted. It now carries the time the user authenticated (the password
      step, even when MFA followed), is stored on the session (migration
      `022`; existing sessions use their creation time), and is unchanged in
      refreshed ID tokens. Relying parties that enforce `max_age` or
      re-authentication windows from `auth_time` will now see older values
      for long-lived sessions, which is the correct behaviour; device-grant
      tokens do not record it and still report the issuance time.

## 4. MFA assurance (**breaking for step-up users**)

Earlier builds marked every code exchange as MFA-verified, even for a
password-only login. Now the ID token's `acr` claim and the session's MFA flag
reflect whether an MFA challenge actually happened (TOTP, WebAuthn, or an
MFA-verified portal session on silent SSO).

- [ ] **AWS roles with `require_step_up_mfa`** are now refused (`403
      step_up_required`) for users who have not enrolled TOTP or a security key.
      Make sure everyone who needs those roles has enrolled before you deploy.
- [ ] **Relying parties that read `acr`** will stop seeing it for
      password-only users. That is the intended fix; confirm none depends on
      the old behaviour.
- [ ] Sessions created before the upgrade keep their stored flag; only new
      code exchanges are affected.

## 5. Audit journal fail-closed

Handlers that change state now refuse to proceed when the audit journal (NATS
JetStream) is unreachable and return `503`: the admin API, the portal admin
(users, clients, groups, integrations, AWS federation config), MFA enrolment and
removal, and self-registration.

- [ ] **Confirm NATS health and alerting** before relying on these paths.
- [ ] **Destructive and credential-weakening actions audit first**: user
      update/deactivate/delete, password reset, compromised-account reset, MFA
      removal (self-service and admin), client delete and secret rotation,
      group delete, AWS account/role/assignment delete, integration delete. A
      journal outage refuses them and leaves the data untouched, so nothing is
      deleted without a record and downstream deprovisioning is never skipped.
      (The AWS delete handlers previously ignored audit errors entirely.)
- [ ] **Creates are rolled back** when their audit write fails (users, clients,
      groups, AWS accounts/roles/assignments, integrations, and both
      self-registration paths): the response is `503` and the new row is
      deleted, so a retry after recovery starts clean. If the rollback itself
      fails, the row remains and `authd` logs `audit failure: could not roll
      back unaudited change` for the operator.
- [ ] Lower-risk changes (profile edits, MFA enrolment, group/client/integration
      updates) still audit last: on failure the response is `503` and
      provisioning is skipped, but the change may already be stored.

## 6. Retired features

### GitHub OAuth compatibility (removed)

The GitHub-API emulation that existed for Teleport is gone, along with the
Teleport dev wiring.

- [ ] Find consumers still using it: requests to `/login/oauth/authorize`,
      `/login/oauth/access_token`, `/api/v3/user*` or `/user*`, or sending
      `Authorization: token …`. They now fail (`404`/`405`/`401`). Move them to
      standard OIDC against `/.well-known/openid-configuration` with
      `Authorization: Bearer …`.
- [ ] Drop any GitHub-style OAuth app, Teleport connector, and Traefik routes
      or certificate names you added for it.

### IAM user/group provisioning (removed)

Outbound provisioning is SCIM; AWS access is OIDC federation
(`AssumeRoleWithWebIdentity`) only.

- [ ] Migration `020` **disables** existing `aws_iam` integrations. It does
      not delete them and **does not touch AWS**. Their rows appear in
      `/portal/admin/integrations` as cleanup-only entries that cannot be
      re-enabled.
- [ ] **Clean up AWS yourself.** For each retired integration, review and
      remove the IAM users, groups, group memberships, access keys and any
      login profiles that auth created, once you have confirmed nobody depends
      on them. Then delete the integration row.
- [ ] Move those users to federation: register the OIDC provider and
      `AUTHD_AWS_AUDIENCE`, create roles with `aws:RequestTag` trust
      conditions, and assign them to groups (see the README's AWS OIDC
      Federation section).
- [ ] Revocation still uses IAM role inline policies; keep `AWS_REGION` and a
      credential source (machine role preferred) if you use it.

## 7. Issuer and WebAuthn relying-party changes

Only if you are changing `AUTHD_ISSUER`, its hostname, or `AUTHD_WEBAUTHN_RPID`:

- [ ] **The RP ID defaults to the hostname of `AUTHD_ISSUER`.** Changing it
      invalidates every registered WebAuthn credential; users must re-enrol.
      A browser only accepts an RP ID that is the origin's host or a
      registrable parent of it, so credentials can survive a hostname move
      only while the new host is still under the old RP ID's domain: pin
      `AUTHD_WEBAUTHN_RPID` to that domain and list every origin in
      `AUTHD_WEBAUTHN_ORIGINS` (`scheme://host[:port]`, no path). A move to an
      unrelated domain always requires re-enrolment.
- [ ] **The `iss` claim changes with the issuer.** Every relying party that
      validates `iss`, and every AWS IAM OIDC provider URL, must be updated, and
      RPs need to re-fetch discovery and JWKS.
- [ ] Redirect URIs, back-channel logout endpoints and Traefik/edge
      certificates must match the new hostname.
- [ ] Existing sessions and tokens carry the old issuer; plan for users to
      sign in again.

## 8. Verify after deploying

- [ ] `authd serve` starts cleanly; logs show the audit sink connected.
- [ ] `GET /.well-known/openid-configuration` reports the expected issuer.
- [ ] A password-only login yields an ID token **without** `acr`; an MFA login
      yields it.
- [ ] A refresh returns a new access token that `/userinfo` accepts, and
      replaying the old refresh token returns `400` and kills that session.
- [ ] One relying party completes a full login (scopes accepted).
- [ ] Stop NATS briefly in staging: admin writes return `503` and the data is
      unchanged.
- [ ] Hammer `/portal/login` from one address: it answers `429` with
      `Retry-After` after the budget, while `/health` stays `200`.
