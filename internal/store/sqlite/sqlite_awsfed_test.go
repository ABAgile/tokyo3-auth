package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/auth"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

func freshDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAWSAccountCRUD(t *testing.T) {
	ctx := context.Background()
	db := freshDB(t)
	a := &model.AWSAccount{AccountID: "111111111111", Alias: "prod", OIDCProviderARN: "arn:aws:iam::111:oidc-provider/id.example.com"}
	if err := db.CreateAWSAccount(ctx, a); err != nil {
		t.Fatalf("CreateAWSAccount: %v", err)
	}
	if a.ID == uuid.Nil {
		t.Error("ID should be populated after create")
	}
	got, err := db.GetAWSAccount(ctx, a.ID)
	if err != nil {
		t.Fatalf("GetAWSAccount: %v", err)
	}
	if got.AccountID != "111111111111" || got.Alias != "prod" {
		t.Errorf("got %+v", got)
	}
	a.Alias = "production"
	if err := db.UpdateAWSAccount(ctx, a); err != nil {
		t.Fatalf("UpdateAWSAccount: %v", err)
	}
	got, _ = db.GetAWSAccount(ctx, a.ID)
	if got.Alias != "production" {
		t.Errorf("alias not updated: %q", got.Alias)
	}
	if err := db.DeleteAWSAccount(ctx, a.ID); err != nil {
		t.Fatalf("DeleteAWSAccount: %v", err)
	}
}

func TestAWSRoleCRUD_AndCascadeOnAccount(t *testing.T) {
	ctx := context.Background()
	db := freshDB(t)
	acct := &model.AWSAccount{AccountID: "222222222222", OIDCProviderARN: "arn:aws:iam::222:oidc-provider/id.example.com"}
	if err := db.CreateAWSAccount(ctx, acct); err != nil {
		t.Fatalf("CreateAWSAccount: %v", err)
	}
	role := &model.AWSRole{
		AccountID:   acct.ID,
		RoleARN:     "arn:aws:iam::222:role/BackendDev",
		Slug:        "backend-dev",
		DisplayName: "Backend: dev",
	}
	if err := db.CreateAWSRole(ctx, role); err != nil {
		t.Fatalf("CreateAWSRole: %v", err)
	}
	if role.MaxSessionDurationSec != 3600 {
		t.Errorf("expected default MaxSessionDurationSec=3600, got %d", role.MaxSessionDurationSec)
	}
	// Account delete must cascade to roles via FK.
	if err := db.DeleteAWSAccount(ctx, acct.ID); err != nil {
		t.Fatalf("DeleteAWSAccount: %v", err)
	}
	if _, err := db.GetAWSRole(ctx, role.ID); err == nil {
		t.Error("expected role to be cascade-deleted with account")
	}
}

// TestListAWSRolesForUser exercises the group-membership join used by the
// portal tile page.
func TestListAWSRolesForUser(t *testing.T) {
	ctx := context.Background()
	db := freshDB(t)

	hash, _ := auth.HashPassword("pw0rd-very-strong-123!")
	user, err := db.CreateUser(ctx, "alice@example.com", hash, "Alice")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	group, err := db.CreateGroup(ctx, "platform")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := db.AddGroupMember(ctx, group.ID, user.ID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	acct := &model.AWSAccount{AccountID: "333333333333", OIDCProviderARN: "arn:aws:iam::333:oidc-provider/id.example.com"}
	_ = db.CreateAWSAccount(ctx, acct)
	role1 := &model.AWSRole{AccountID: acct.ID, RoleARN: "arn:aws:iam::333:role/A", Slug: "role-a", DisplayName: "A"}
	role2 := &model.AWSRole{AccountID: acct.ID, RoleARN: "arn:aws:iam::333:role/B", Slug: "role-b", DisplayName: "B"}
	_ = db.CreateAWSRole(ctx, role1)
	_ = db.CreateAWSRole(ctx, role2)
	if err := db.CreateAWSRoleAssignment(ctx, &model.AWSRoleAssignment{GroupID: group.ID, RoleID: role1.ID}); err != nil {
		t.Fatalf("CreateAWSRoleAssignment: %v", err)
	}

	roles, err := db.ListAWSRolesForUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("ListAWSRolesForUser: %v", err)
	}
	if len(roles) != 1 || roles[0].ID != role1.ID {
		t.Errorf("expected only role1 (%s) assigned to alice; got %v", role1.ID, roles)
	}
}

func TestAWSRevokedUsers_AddIsIdempotent_ListAndReap(t *testing.T) {
	ctx := context.Background()
	db := freshDB(t)
	acct := &model.AWSAccount{AccountID: "444444444444", OIDCProviderARN: "arn:aws:iam::444:oidc-provider/id.example.com"}
	_ = db.CreateAWSAccount(ctx, acct)
	role := &model.AWSRole{AccountID: acct.ID, RoleARN: "arn:aws:iam::444:role/R", Slug: "role-r", DisplayName: "R"}
	_ = db.CreateAWSRole(ctx, role)

	if err := db.AddAWSRevokedUser(ctx, role.ID, "alice-uuid"); err != nil {
		t.Fatalf("AddAWSRevokedUser: %v", err)
	}
	// Adding the same pair again should not error and should remain one row.
	if err := db.AddAWSRevokedUser(ctx, role.ID, "alice-uuid"); err != nil {
		t.Fatalf("AddAWSRevokedUser (idempotent): %v", err)
	}
	rows, _ := db.ListAWSRevokedUsers(ctx, role.ID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 row after idempotent re-add, got %d", len(rows))
	}

	// Synthesise a second, older row by direct INSERT with backdated time.
	// Uses the same canonical timestamp format the store layer writes so
	// julianday() comparisons work consistently.
	old := time.Now().Add(-24 * time.Hour)
	_, err := db.db.ExecContext(ctx,
		`INSERT INTO aws_revoked_users (role_id, sub_uuid, revoked_at) VALUES (?, ?, ?)`,
		role.ID, "bob-uuid", dt(old))
	if err != nil {
		t.Fatalf("backdate insert: %v", err)
	}
	cutoff := time.Now().Add(-1 * time.Hour)
	old1, err := db.ListAWSRevokedUsersOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("ListAWSRevokedUsersOlderThan: %v", err)
	}
	var subs []string
	for _, r := range old1 {
		subs = append(subs, r.SubUUID)
	}
	if len(old1) != 1 || old1[0].SubUUID != "bob-uuid" {
		t.Errorf("expected only bob-uuid older than cutoff, got %v", subs)
	}
	if err := db.DeleteAWSRevokedUser(ctx, role.ID, "bob-uuid"); err != nil {
		t.Fatalf("DeleteAWSRevokedUser: %v", err)
	}
}
