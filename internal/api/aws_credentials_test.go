package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/google/uuid"
)

// seedSessionWithToken creates an active OAuth session for a user, returns
// the raw access token so tests can present it as a bearer credential.
func seedSessionWithToken(t *testing.T, r *testRig, userID uuid.UUID, mfa bool) string {
	t.Helper()
	rawAccess, _ := creds.GenerateRawToken()
	rawRefresh, _ := creds.GenerateRawToken()
	now := time.Now().UTC().Truncate(time.Second)
	c, err := r.store.CreateClient(context.Background(),
		"awscreds-test-cid-"+rawAccess[:8], creds.HashToken("nope"),
		"awscreds-test", []string{"http://localhost/cb"}, []string{"openid"}, false, nil)
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	sess := &model.Session{
		ID: uuid.New(), UserID: userID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(rawAccess),
		RefreshTokenHash: creds.HashToken(rawRefresh),
		Scopes:           []string{"openid"},
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshExpiresAt: now.Add(2 * time.Hour),
		MFAVerified:      mfa,
		CreatedAt:        now,
	}
	if err := r.store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return rawAccess
}

// seedAWSCatalog creates one account + one role with the given slug, and
// assigns the user (via a fresh SCIM group) to that role.
func seedAWSCatalog(t *testing.T, r *testRig, user *model.User, slug string, requireMFA bool) *model.AWSRole {
	t.Helper()
	ctx := context.Background()
	acct := &model.AWSAccount{
		AccountID:       "111111111111",
		OIDCProviderARN: "arn:aws:iam::111:oidc-provider/test",
	}
	if err := r.store.CreateAWSAccount(ctx, acct); err != nil {
		t.Fatalf("CreateAWSAccount: %v", err)
	}
	role := &model.AWSRole{
		AccountID:             acct.ID,
		RoleARN:               "arn:aws:iam::111:role/Test-" + slug,
		Slug:                  slug,
		DisplayName:           slug,
		RequireStepUpMFA:      requireMFA,
		MaxSessionDurationSec: 3600,
	}
	if err := r.store.CreateAWSRole(ctx, role); err != nil {
		t.Fatalf("CreateAWSRole: %v", err)
	}
	grp, err := r.store.CreateGroup(ctx, "awscreds-test-grp-"+slug)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := r.store.AddGroupMember(ctx, grp.ID, user.ID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	if err := r.store.CreateAWSRoleAssignment(ctx, &model.AWSRoleAssignment{
		GroupID: grp.ID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("CreateAWSRoleAssignment: %v", err)
	}
	return role
}

// postCredentials issues a bearer-authenticated POST to /aws/credentials
// with the given form body. Helper because every test below needs the
// same three-line setup.
func postCredentials(t *testing.T, r *testRig, bearer, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, r.srv.URL+"/aws/credentials", strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{CheckRedirect: noFollow}).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}

// TestAWSCredentials_RequiresBearer guards the auth middleware — requests
// without a bearer token must be rejected before any role lookup happens.
func TestAWSCredentials_RequiresBearer(t *testing.T) {
	r := newTestRig(t)
	resp := postCredentials(t, r, "", "role=any")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// TestAWSCredentials_RequiresRole asserts the form validation — a
// bearer-authenticated request without a role parameter should fail at
// the input check, not at role lookup.
func TestAWSCredentials_RequiresRole(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "alice@example.com", "P@ssw0rd1234")
	token := seedSessionWithToken(t, r, u.ID, false)

	resp := postCredentials(t, r, token, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// TestAWSCredentials_DeprecatedAudienceAlias verifies the 0.x → 1.x
// migration path still works: requests using the legacy `audience` form
// field reach the slug-based lookup unchanged. Drop this test (and the
// alias) after one release cycle.
func TestAWSCredentials_DeprecatedAudienceAlias(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "alice@example.com", "P@ssw0rd1234")
	_ = seedAWSCatalog(t, r, u, "platform-prod", false)
	token := seedSessionWithToken(t, r, u.ID, false)

	form := url.Values{"audience": {"platform-prod"}}
	resp := postCredentials(t, r, token, form.Encode())
	defer resp.Body.Close()
	// Without a real STS endpoint this still 502s at the STS call, but
	// the slug must have RESOLVED (otherwise we'd see 403 not_assigned).
	// Either way, the deprecated alias must not 400 with "role required".
	if resp.StatusCode == http.StatusBadRequest {
		t.Errorf("deprecated audience alias dropped to 400; alias path broken")
	}
}

// TestAWSCredentials_UnassignedSlugReturns403 verifies that even when
// authenticated, a user cannot request credentials for a slug their
// groups don't grant. Collapses "slug unknown" and "slug not assigned"
// to the same 403 so the catalogue isn't leaked to unauthorised callers.
func TestAWSCredentials_UnassignedSlugReturns403(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "alice@example.com", "P@ssw0rd1234")
	token := seedSessionWithToken(t, r, u.ID, false)

	form := url.Values{"role": {"never-assigned"}}
	resp := postCredentials(t, r, token, form.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

// TestAWSCredentials_StepUpRequiredWithoutMFA confirms the MFA gate —
// a user without an MFA-verified session cannot assume a role flagged
// require_step_up_mfa, even if their groups would otherwise grant access.
func TestAWSCredentials_StepUpRequiredWithoutMFA(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "alice@example.com", "P@ssw0rd1234")
	token := seedSessionWithToken(t, r, u.ID, false) // MFA NOT verified
	_ = seedAWSCatalog(t, r, u, "locked-role", true)

	form := url.Values{"role": {"locked-role"}}
	resp := postCredentials(t, r, token, form.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (step_up_required)", resp.StatusCode)
	}
}

// TestAWSCredentials_DeactivatedUserIs403 covers the user-state check
// that's the deactivation safety net for credential issuance — even with
// a valid (non-expired) bearer token, a deactivated user must not be
// able to mint new AWS credentials. Belt-and-suspenders with the
// awsfed revocation provisioner.
func TestAWSCredentials_DeactivatedUserIs403(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "alice@example.com", "P@ssw0rd1234")
	token := seedSessionWithToken(t, r, u.ID, false)
	_ = seedAWSCatalog(t, r, u, "active-role", false)

	if err := r.store.SetUserActive(context.Background(), u.ID, false); err != nil {
		t.Fatalf("SetUserActive: %v", err)
	}

	form := url.Values{"role": {"active-role"}}
	resp := postCredentials(t, r, token, form.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (user_inactive)", resp.StatusCode)
	}
}

// TestAWSCredentials_FederationDisabledReturns503 asserts that the
// endpoint refuses with a clear server-misconfiguration error when
// AUTHD_AWS_AUDIENCE is unset. Operators see this immediately rather
// than chasing an opaque AWS-side "InvalidIdentityToken" rejection.
func TestAWSCredentials_FederationDisabledReturns503(t *testing.T) {
	r := newTestRig(t)
	// Override the rig's awsAudience to empty for this one test.
	r.server.awsAudience = ""

	u := seedTestUser(t, r.store, "alice@example.com", "P@ssw0rd1234")
	token := seedSessionWithToken(t, r, u.ID, false)

	form := url.Values{"role": {"any"}}
	resp := postCredentials(t, r, token, form.Encode())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (federation_disabled)", resp.StatusCode)
	}
}
