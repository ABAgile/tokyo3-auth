package api

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

// TestAuthorizingGroupsForRole pins the contract that drives the `team`
// session tag: the helper must return only groups that BOTH contain the
// user AND are mapped to the target role, sorted lexicographically so
// the caller (assumeRoleForUser) gets a deterministic pick. A regression
// here would silently break per-role aws:RequestTag/team gating for any
// user with multiple group memberships — exactly the bug this method
// was introduced to fix.
func TestAuthorizingGroupsForRole(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()

	user := seedTestUser(t, r.store, "alice@example.com", "P@ssw0rd1234")
	other := seedTestUser(t, r.store, "bob@example.com", "P@ssw0rd1234")

	acct := &model.AWSAccount{
		AccountID:       "222222222222",
		OIDCProviderARN: "arn:aws:iam::222:oidc-provider/test",
	}
	if err := r.store.CreateAWSAccount(ctx, acct); err != nil {
		t.Fatalf("CreateAWSAccount: %v", err)
	}

	mkRole := func(slug string) *model.AWSRole {
		role := &model.AWSRole{
			AccountID:             acct.ID,
			RoleARN:               "arn:aws:iam::222:role/" + slug,
			Slug:                  slug,
			DisplayName:           slug,
			MaxSessionDurationSec: 3600,
		}
		if err := r.store.CreateAWSRole(ctx, role); err != nil {
			t.Fatalf("CreateAWSRole(%s): %v", slug, err)
		}
		return role
	}
	mkGroup := func(name string, members ...uuid.UUID) *model.SCIMGroup {
		g, err := r.store.CreateGroup(ctx, name)
		if err != nil {
			t.Fatalf("CreateGroup(%s): %v", name, err)
		}
		for _, m := range members {
			if err := r.store.AddGroupMember(ctx, g.ID, m); err != nil {
				t.Fatalf("AddGroupMember(%s, %s): %v", name, m, err)
			}
		}
		return g
	}
	assign := func(group *model.SCIMGroup, role *model.AWSRole) {
		if err := r.store.CreateAWSRoleAssignment(ctx, &model.AWSRoleAssignment{
			GroupID: group.ID, RoleID: role.ID,
		}); err != nil {
			t.Fatalf("CreateAWSRoleAssignment: %v", err)
		}
	}

	// Catalogue:
	//   roleAlpha   ← gBravo (alice), gAlpha (alice)   → two authorizing groups
	//   roleBeta    ← gCharlie (bob only)              → alice not authorized
	//   roleGamma   ← (no assignments)                 → nothing authorizes it
	//   gDelta — alice is a member but it maps to nothing
	roleAlpha := mkRole("alpha")
	roleBeta := mkRole("beta")
	roleGamma := mkRole("gamma")

	gAlpha := mkGroup("g-alpha", user.ID)
	gBravo := mkGroup("g-bravo", user.ID)
	gCharlie := mkGroup("g-charlie", other.ID)
	_ = mkGroup("g-delta", user.ID) // unmapped membership noise

	// Deliberately assign in non-alphabetical order so the test verifies
	// the helper sorts the result rather than relying on insertion order.
	assign(gBravo, roleAlpha)
	assign(gAlpha, roleAlpha)
	assign(gCharlie, roleBeta)

	tests := []struct {
		name   string
		userID uuid.UUID
		roleID uuid.UUID
		want   []string
	}{
		{
			name:   "two authorizing groups returned sorted",
			userID: user.ID,
			roleID: roleAlpha.ID,
			want:   []string{"g-alpha", "g-bravo"},
		},
		{
			name:   "role assigned but user not in any mapped group",
			userID: user.ID,
			roleID: roleBeta.ID,
			want:   nil,
		},
		{
			name:   "role has no assignments at all",
			userID: user.ID,
			roleID: roleGamma.ID,
			want:   nil,
		},
		{
			name:   "user has no relevant memberships",
			userID: other.ID,
			roleID: roleAlpha.ID,
			want:   nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.server.authorizingGroupsForRole(ctx, tc.userID, tc.roleID)
			if err != nil {
				t.Fatalf("authorizingGroupsForRole: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSigninFedURLForRegion pins the fix for opt-in AWS regions (e.g.
// ap-east-2 / Taipei): they have their own signin domain and reject a
// session minted at the global one. Empty region must keep today's
// global behavior unchanged.
func TestSigninFedURLForRegion(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"empty region keeps global endpoint", "", "https://signin.aws.amazon.com/federation"},
		{"opt-in region gets its own domain", "ap-east-2", "https://ap-east-2.signin.aws.amazon.com/federation"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := signinFedURLForRegion(tc.region); got != tc.want {
				t.Errorf("signinFedURLForRegion(%q) = %q, want %q", tc.region, got, tc.want)
			}
		})
	}
}

func TestConsoleHomeURLForRegion(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"empty region keeps global console home", "", "https://console.aws.amazon.com/"},
		{"opt-in region gets a regional console home", "ap-east-2", "https://ap-east-2.console.aws.amazon.com/console/home?region=ap-east-2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := consoleHomeURLForRegion(tc.region); got != tc.want {
				t.Errorf("consoleHomeURLForRegion(%q) = %q, want %q", tc.region, got, tc.want)
			}
		})
	}
}

// TestBuildConsoleLoginURL pins that the login Action is always posted to
// the SAME fedURL the SigninToken was minted against — mixing the global
// and regional domains is exactly the bug this fix closes.
func TestBuildConsoleLoginURL(t *testing.T) {
	got := buildConsoleLoginURL("tok123", "https://issuer.example/refresh", "https://ap-east-2.console.aws.amazon.com/console/home?region=ap-east-2", "https://ap-east-2.signin.aws.amazon.com/federation")
	want := "https://ap-east-2.signin.aws.amazon.com/federation?Action=login&Destination=https%3A%2F%2Fap-east-2.console.aws.amazon.com%2Fconsole%2Fhome%3Fregion%3Dap-east-2&Issuer=https%3A%2F%2Fissuer.example%2Frefresh&SigninToken=tok123"
	if got != want {
		t.Errorf("buildConsoleLoginURL() = %q, want %q", got, want)
	}
}

// TestSTSClientForRegion pins that credentials are minted at the
// matching regional STS endpoint when a region is given, and at the
// existing global one when it is not. This is the other half of the
// opt-in region fix: AWS documents that session tokens minted at the
// global STS endpoint are only valid in regions enabled by default, so
// an opt-in region needs its own regional endpoint's tokens regardless
// of which signin domain they're later presented to.
func TestSTSClientForRegion(t *testing.T) {
	r := newTestRig(t)

	tests := []struct {
		name          string
		region        string
		wantEndpoint  string
		wantSDKRegion string
	}{
		{"empty region keeps the global STS endpoint", "", "https://sts.amazonaws.com", "us-east-1"},
		{"opt-in region gets its own STS endpoint", "ap-east-2", "https://sts.ap-east-2.amazonaws.com", "ap-east-2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, ok := r.server.stsClientForRegion(tc.region).(*sts.Client)
			if !ok {
				t.Fatalf("stsClientForRegion(%q) did not return a *sts.Client", tc.region)
			}
			opts := client.Options()
			if got := aws.ToString(opts.BaseEndpoint); got != tc.wantEndpoint {
				t.Errorf("BaseEndpoint = %q, want %q", got, tc.wantEndpoint)
			}
			if opts.Region != tc.wantSDKRegion {
				t.Errorf("Region = %q, want %q", opts.Region, tc.wantSDKRegion)
			}
		})
	}
}

// TestSanitizeAWSRegion pins that the `region` request parameter — which
// comes straight from which "Open Console" button the browser clicked —
// is rejected (falls back to "", the global domains) unless it matches a
// syntactically safe AWS region name. A value containing "/" or "@" would
// otherwise change which host authd's own server-side HTTP call in
// exchangeSigninToken actually dials.
func TestSanitizeAWSRegion(t *testing.T) {
	tests := []struct {
		name   string
		region string
		want   string
	}{
		{"empty stays empty", "", ""},
		{"known region passes through", "ap-east-2", "ap-east-2"},
		{"other known region passes through", "ap-southeast-1", "ap-southeast-1"},
		{"path injection rejected", "evil.com/x", ""},
		{"userinfo injection rejected", "evil.com@x", ""},
		{"query injection rejected", "x?evil=1", ""},
		{"uppercase rejected", "AP-EAST-2", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeAWSRegion(tc.region); got != tc.want {
				t.Errorf("sanitizeAWSRegion(%q) = %q, want %q", tc.region, got, tc.want)
			}
		})
	}
}
