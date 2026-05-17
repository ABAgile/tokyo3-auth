package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// Compile-time assertion: *DB satisfies the full store.Store contract.
var _ store.Store = (*DB)(nil)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	// In-memory DB; the modernc.org/sqlite driver supports ":memory:" but we
	// need a single shared connection for it to behave like one DB across
	// queries — Open() already caps MaxOpenConns to 1.
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMigrationsApply confirms every embedded migration applies on a fresh
// DB and that the schema_migrations tracking table records each one.
func TestMigrationsApply(t *testing.T) {
	db := openTestDB(t)

	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n != 12 {
		t.Errorf("expected 12 migrations applied, got %d", n)
	}

	// Re-running migrate() must be a no-op (idempotent).
	if err := db.migrate(); err != nil {
		t.Fatalf("migrate idempotency: %v", err)
	}
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations 2: %v", err)
	}
	if n != 12 {
		t.Errorf("after re-run, expected still 12 migrations, got %d", n)
	}
}

// TestUserRoundTrip exercises the user CRUD path end-to-end including the
// nullable LockedUntil column (a common Postgres → SQLite porting pitfall).
func TestUserRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u, err := db.CreateUser(ctx, "alice@example.com", "hash", "Alice")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == uuid.Nil {
		t.Fatal("expected ID, got nil UUID")
	}
	if !u.Active {
		t.Errorf("expected Active=true (default), got false")
	}
	if u.LockedUntil != nil {
		t.Errorf("expected LockedUntil=nil, got %v", *u.LockedUntil)
	}

	// Lock the account, confirm the nullable column round-trips.
	until := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
	if err := db.UpdateUserFailedAttempts(ctx, u.ID, 3, &until); err != nil {
		t.Fatalf("UpdateUserFailedAttempts: %v", err)
	}
	got, err := db.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.FailedAttempts != 3 {
		t.Errorf("FailedAttempts: want 3, got %d", got.FailedAttempts)
	}
	if got.LockedUntil == nil {
		t.Fatal("expected LockedUntil set, got nil")
	}
	if !got.LockedUntil.Equal(until) {
		t.Errorf("LockedUntil: want %v, got %v", until, *got.LockedUntil)
	}

	// Clear the lock — back to NULL.
	if err := db.UpdateUserFailedAttempts(ctx, u.ID, 0, nil); err != nil {
		t.Fatalf("UpdateUserFailedAttempts clear: %v", err)
	}
	got, err = db.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID 2: %v", err)
	}
	if got.LockedUntil != nil {
		t.Errorf("expected LockedUntil cleared, got %v", *got.LockedUntil)
	}

	// Duplicate email → ErrConflict.
	if _, err := db.CreateUser(ctx, "alice@example.com", "h", "A2"); err != store.ErrConflict {
		t.Errorf("duplicate email: want ErrConflict, got %v", err)
	}

	// Lookup-miss → ErrNotFound.
	if _, err := db.GetUserByID(ctx, uuid.New()); err != store.ErrNotFound {
		t.Errorf("missing user: want ErrNotFound, got %v", err)
	}
}

// TestClientArrayRoundTrip exercises the JSON-encoded TEXT[] equivalent for
// redirect_uris/scopes — the most error-prone part of the postgres → sqlite port.
func TestClientArrayRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	uris := []string{"https://app.example/callback", "https://alt.example/cb"}
	scopes := []string{"openid", "email", "profile"}
	c, err := db.CreateClient(ctx, "my-app", "secrethash", "My App", uris, scopes, false, nil)
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	got, err := db.GetClientByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetClientByID: %v", err)
	}
	if !sliceEq(got.RedirectURIs, uris) {
		t.Errorf("RedirectURIs: want %v, got %v", uris, got.RedirectURIs)
	}
	if !sliceEq(got.Scopes, scopes) {
		t.Errorf("Scopes: want %v, got %v", scopes, got.Scopes)
	}

	// Empty array round-trip.
	if err := db.UpdateClient(ctx, c.ID, "Renamed", nil, nil, true, nil); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	got, err = db.GetClientByID(ctx, c.ID)
	if err != nil {
		t.Fatalf("GetClientByID 2: %v", err)
	}
	if len(got.RedirectURIs) != 0 {
		t.Errorf("expected empty RedirectURIs, got %v", got.RedirectURIs)
	}
	if len(got.Scopes) != 0 {
		t.Errorf("expected empty Scopes, got %v", got.Scopes)
	}
	if !got.Public {
		t.Error("Public: want true, got false")
	}
}

// TestPortalClientSeed confirms migration 005 inserted the well-known portal
// sentinel client.
func TestPortalClientSeed(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	c, err := db.GetClientByClientID(ctx, "portal")
	if err != nil {
		t.Fatalf("portal seed missing: %v", err)
	}
	if c.ID.String() != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("portal client ID mismatch: %s", c.ID)
	}
	if !c.Public {
		t.Error("portal client should be public")
	}
	if !sliceEq(c.Scopes, []string{"portal", "admin"}) {
		t.Errorf("portal scopes mismatch: %v", c.Scopes)
	}
}

// TestExternalIDsUpsert covers the ON CONFLICT DO UPDATE syntax difference.
func TestExternalIDsUpsert(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	user, err := db.CreateUser(ctx, "carol@example.com", "h", "Carol")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := db.SetExternalID(ctx, "vault", user.ID, "ext-1"); err != nil {
		t.Fatalf("SetExternalID first: %v", err)
	}
	got, err := db.GetExternalID(ctx, "vault", user.ID)
	if err != nil {
		t.Fatalf("GetExternalID: %v", err)
	}
	if got != "ext-1" {
		t.Errorf("want ext-1, got %s", got)
	}

	// Upsert: same (provider,user) should overwrite.
	if err := db.SetExternalID(ctx, "vault", user.ID, "ext-2"); err != nil {
		t.Fatalf("SetExternalID upsert: %v", err)
	}
	got, err = db.GetExternalID(ctx, "vault", user.ID)
	if err != nil {
		t.Fatalf("GetExternalID 2: %v", err)
	}
	if got != "ext-2" {
		t.Errorf("after upsert: want ext-2, got %s", got)
	}
}

// TestGroupMembersIdempotent covers the ON CONFLICT (group_id,user_id)
// DO NOTHING upsert in ReplaceGroupMembers / AddGroupMember.
func TestGroupMembersIdempotent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	u1, err := db.CreateUser(ctx, "u1@example.com", "h", "U1")
	if err != nil {
		t.Fatalf("CreateUser u1: %v", err)
	}
	u2, err := db.CreateUser(ctx, "u2@example.com", "h", "U2")
	if err != nil {
		t.Fatalf("CreateUser u2: %v", err)
	}

	g, err := db.CreateGroup(ctx, "engineers")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := db.AddGroupMember(ctx, g.ID, u1.ID); err != nil {
		t.Fatalf("AddGroupMember 1: %v", err)
	}
	// Duplicate add: must not error.
	if err := db.AddGroupMember(ctx, g.ID, u1.ID); err != nil {
		t.Fatalf("AddGroupMember dup: %v", err)
	}

	if err := db.ReplaceGroupMembers(ctx, g.ID, []uuid.UUID{u1.ID, u2.ID, u1.ID}); err != nil {
		t.Fatalf("ReplaceGroupMembers with dup: %v", err)
	}
	got, err := db.GetGroupByID(ctx, g.ID)
	if err != nil {
		t.Fatalf("GetGroupByID: %v", err)
	}
	if len(got.Members) != 2 {
		t.Errorf("want 2 distinct members, got %d (%v)", len(got.Members), got.Members)
	}
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
