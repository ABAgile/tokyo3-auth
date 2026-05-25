package api

import (
	"context"
	"reflect"
	"testing"

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
