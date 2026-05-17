package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// Helper to create a user + client pair every "operational" test needs.
func newUserAndClient(t *testing.T, db *DB) (*model.User, *model.Client) {
	t.Helper()
	ctx := context.Background()
	u, err := db.CreateUser(ctx, t.Name()+"@example.com", "hash", t.Name())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	c, err := db.CreateClient(ctx, t.Name()+"-client", "sec", t.Name()+" app",
		[]string{"https://app.example/cb"}, []string{"openid"}, false, nil)
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return u, c
}

// ── Grants ────────────────────────────────────────────────────────────────────

func TestGrantRoundTrip(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)

	g := &model.Grant{
		ID:            uuid.New(),
		UserID:        u.ID,
		ClientID:      c.ID,
		CodeHash:      "code-hash-1",
		CodeChallenge: "S256-challenge",
		Nonce:         "nonce-1",
		Scopes:        []string{"openid", "email"},
		RedirectURI:   "https://app.example/cb",
		ExpiresAt:     time.Now().Add(time.Minute).UTC().Truncate(time.Second),
	}
	if err := db.CreateGrant(ctx, g); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}

	got, err := db.GetGrantByCodeHash(ctx, "code-hash-1")
	if err != nil {
		t.Fatalf("GetGrantByCodeHash: %v", err)
	}
	if got.UsedAt != nil {
		t.Errorf("UsedAt: want nil, got %v", *got.UsedAt)
	}
	if !sliceEq(got.Scopes, []string{"openid", "email"}) {
		t.Errorf("scopes round-trip: got %v", got.Scopes)
	}

	if err := db.MarkGrantUsed(ctx, g.ID); err != nil {
		t.Fatalf("MarkGrantUsed: %v", err)
	}
	got, err = db.GetGrantByCodeHash(ctx, "code-hash-1")
	if err != nil {
		t.Fatalf("GetGrantByCodeHash 2: %v", err)
	}
	if got.UsedAt == nil {
		t.Error("UsedAt: want set after MarkGrantUsed, got nil")
	}

	if _, err := db.GetGrantByCodeHash(ctx, "missing"); err != store.ErrNotFound {
		t.Errorf("missing code: want ErrNotFound, got %v", err)
	}
}

func TestGrantDeleteExpired(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)

	fresh := &model.Grant{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		CodeHash: "fresh", ExpiresAt: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
	}
	stale := &model.Grant{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		CodeHash: "stale", ExpiresAt: time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second),
	}
	if err := db.CreateGrant(ctx, fresh); err != nil {
		t.Fatalf("CreateGrant fresh: %v", err)
	}
	if err := db.CreateGrant(ctx, stale); err != nil {
		t.Fatalf("CreateGrant stale: %v", err)
	}
	if err := db.DeleteExpiredGrants(ctx); err != nil {
		t.Fatalf("DeleteExpiredGrants: %v", err)
	}
	if _, err := db.GetGrantByCodeHash(ctx, "fresh"); err != nil {
		t.Errorf("fresh should survive: %v", err)
	}
	if _, err := db.GetGrantByCodeHash(ctx, "stale"); err != store.ErrNotFound {
		t.Errorf("stale should be gone: got %v", err)
	}
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func TestSessionLifecycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)

	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  "ah-1",
		RefreshTokenHash: "rh-1",
		Scopes:           []string{"openid"},
		AccessExpiresAt:  time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		RefreshExpiresAt: time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second),
		MFAVerified:      true,
	}
	if err := db.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := db.GetSessionByAccessTokenHash(ctx, "ah-1")
	if err != nil {
		t.Fatalf("GetSessionByAccessTokenHash: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("session id mismatch")
	}
	if !got.MFAVerified {
		t.Error("MFAVerified should be true")
	}

	got, err = db.GetSessionByRefreshTokenHash(ctx, "rh-1")
	if err != nil {
		t.Fatalf("GetSessionByRefreshTokenHash: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("session id mismatch (refresh lookup)")
	}

	// Activity slide.
	la := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	if err := db.UpdateSessionActivity(ctx, sess.ID, la); err != nil {
		t.Fatalf("UpdateSessionActivity: %v", err)
	}
	got, _ = db.GetSessionByAccessTokenHash(ctx, "ah-1")
	if !got.LastActivityAt.Equal(la) {
		t.Errorf("LastActivityAt = %v, want %v", got.LastActivityAt, la)
	}

	// Extend access expiry.
	newExp := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
	if err := db.ExtendSessionExpiry(ctx, sess.ID, newExp); err != nil {
		t.Fatalf("ExtendSessionExpiry: %v", err)
	}
	got, _ = db.GetSessionByAccessTokenHash(ctx, "ah-1")
	if !got.AccessExpiresAt.Equal(newExp) {
		t.Errorf("AccessExpiresAt = %v, want %v", got.AccessExpiresAt, newExp)
	}

	// Rotate refresh.
	newAcc := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	newRef := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	if err := db.RotateRefreshToken(ctx, sess.ID, "rh-2", newAcc, newRef); err != nil {
		t.Fatalf("RotateRefreshToken: %v", err)
	}
	if _, err := db.GetSessionByRefreshTokenHash(ctx, "rh-1"); err != store.ErrNotFound {
		t.Errorf("old refresh hash should be gone: got %v", err)
	}
	if _, err := db.GetSessionByRefreshTokenHash(ctx, "rh-2"); err != nil {
		t.Errorf("new refresh hash should resolve: %v", err)
	}

	// ListSessionClientIDsByUser.
	ids, err := db.ListSessionClientIDsByUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListSessionClientIDsByUser: %v", err)
	}
	if len(ids) != 1 || ids[0] != c.ID {
		t.Errorf("client ids: want [%s], got %v", c.ID, ids)
	}

	// DeleteSession.
	if err := db.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := db.GetSessionByAccessTokenHash(ctx, "ah-1"); err != store.ErrNotFound {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

func TestSessionsByUserBulkDelete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)

	for i, ah := range []string{"a1", "a2", "a3"} {
		s := &model.Session{
			ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
			AccessTokenHash:  ah,
			RefreshTokenHash: "r" + string(rune('1'+i)),
			AccessExpiresAt:  time.Now().Add(time.Hour),
			RefreshExpiresAt: time.Now().Add(24 * time.Hour),
		}
		if err := db.CreateSession(ctx, s); err != nil {
			t.Fatalf("CreateSession[%d]: %v", i, err)
		}
	}
	if err := db.DeleteSessionsByUserID(ctx, u.ID); err != nil {
		t.Fatalf("DeleteSessionsByUserID: %v", err)
	}
	for _, ah := range []string{"a1", "a2", "a3"} {
		if _, err := db.GetSessionByAccessTokenHash(ctx, ah); err != store.ErrNotFound {
			t.Errorf("session %s: want ErrNotFound, got %v", ah, err)
		}
	}
}

func TestSessionDeleteExpired(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)

	// Force timestamps well outside CURRENT_TIMESTAMP's 1-second resolution
	// window — Go time.Time and SQLite's literal differ in timezone notation
	// and a tight window can compare unfavourably under lexical text comparison.
	future := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	past := time.Now().Add(-24 * time.Hour).UTC().Truncate(time.Second)
	fresh := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash: "fresh-a", RefreshTokenHash: "fresh-r",
		AccessExpiresAt: future, RefreshExpiresAt: future,
	}
	stale := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash: "stale-a", RefreshTokenHash: "stale-r",
		AccessExpiresAt: past, RefreshExpiresAt: past,
	}
	if err := db.CreateSession(ctx, fresh); err != nil {
		t.Fatalf("CreateSession fresh: %v", err)
	}
	if err := db.CreateSession(ctx, stale); err != nil {
		t.Fatalf("CreateSession stale: %v", err)
	}
	if err := db.DeleteExpiredSessions(ctx); err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if _, err := db.GetSessionByAccessTokenHash(ctx, "fresh-a"); err != nil {
		t.Errorf("fresh session should survive: %v", err)
	}
	if _, err := db.GetSessionByAccessTokenHash(ctx, "stale-a"); err != store.ErrNotFound {
		t.Errorf("stale session should be gone: got %v", err)
	}
}

// ── TOTP ──────────────────────────────────────────────────────────────────────

func TestTOTPLifecycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, _ := newUserAndClient(t, db)

	c := &model.TOTPCredential{
		ID: uuid.New(), UserID: u.ID,
		EncryptedSecret: []byte("encrypted"), EncryptedDEK: []byte("dek"),
	}
	if err := db.CreateTOTPCredential(ctx, c); err != nil {
		t.Fatalf("CreateTOTPCredential: %v", err)
	}

	got, err := db.GetTOTPByUserID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetTOTPByUserID: %v", err)
	}
	if got.Enabled {
		t.Error("expected disabled on create")
	}

	// Duplicate user → conflict.
	dup := &model.TOTPCredential{ID: uuid.New(), UserID: u.ID, EncryptedSecret: []byte("x"), EncryptedDEK: []byte("y")}
	if err := db.CreateTOTPCredential(ctx, dup); err != store.ErrConflict {
		t.Errorf("dup TOTP: want ErrConflict, got %v", err)
	}

	if err := db.EnableTOTP(ctx, c.ID); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}
	got, _ = db.GetTOTPByUserID(ctx, u.ID)
	if !got.Enabled {
		t.Error("after Enable: expected enabled=true")
	}

	if err := db.DeleteTOTP(ctx, u.ID); err != nil {
		t.Fatalf("DeleteTOTP: %v", err)
	}
	if _, err := db.GetTOTPByUserID(ctx, u.ID); err != store.ErrNotFound {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

// ── WebAuthn ──────────────────────────────────────────────────────────────────

func TestWebAuthnCredentialLifecycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, _ := newUserAndClient(t, db)

	cred := &model.WebAuthnCredential{
		ID: uuid.New(), UserID: u.ID,
		CredentialID: []byte{1, 2, 3, 4},
		PublicKey:    []byte{0xAA, 0xBB},
		AAGUID:       []byte{0xCC},
		SignCount:    7,
		DeviceName:   "yubikey",
	}
	if err := db.CreateWebAuthnCredential(ctx, cred); err != nil {
		t.Fatalf("CreateWebAuthnCredential: %v", err)
	}

	list, err := db.ListWebAuthnCredentials(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListWebAuthnCredentials: %v", err)
	}
	if len(list) != 1 || list[0].DeviceName != "yubikey" {
		t.Errorf("list: %v", list)
	}

	got, err := db.GetWebAuthnCredentialByCredentialID(ctx, []byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("GetWebAuthnCredentialByCredentialID: %v", err)
	}
	if got.SignCount != 7 {
		t.Errorf("SignCount: want 7, got %d", got.SignCount)
	}

	// Duplicate credential_id → ErrConflict.
	dup := &model.WebAuthnCredential{
		ID: uuid.New(), UserID: u.ID,
		CredentialID: []byte{1, 2, 3, 4},
		PublicKey:    []byte{0x01},
		AAGUID:       []byte{0x02},
	}
	if err := db.CreateWebAuthnCredential(ctx, dup); err != store.ErrConflict {
		t.Errorf("dup credential_id: want ErrConflict, got %v", err)
	}

	last := time.Now().UTC().Truncate(time.Second)
	if err := db.UpdateWebAuthnSignCount(ctx, cred.ID, 42, last); err != nil {
		t.Fatalf("UpdateWebAuthnSignCount: %v", err)
	}
	got, _ = db.GetWebAuthnCredentialByCredentialID(ctx, []byte{1, 2, 3, 4})
	if got.SignCount != 42 || !got.LastUsedAt.Equal(last) {
		t.Errorf("after update: SignCount=%d LastUsedAt=%v", got.SignCount, got.LastUsedAt)
	}

	// Cross-user delete must be a no-op.
	if err := db.DeleteWebAuthnCredential(ctx, cred.ID, uuid.New()); err != nil {
		t.Fatalf("cross-user delete err: %v", err)
	}
	list, _ = db.ListWebAuthnCredentials(ctx, u.ID)
	if len(list) != 1 {
		t.Error("cross-user delete should have been a no-op")
	}

	if err := db.DeleteWebAuthnCredential(ctx, cred.ID, u.ID); err != nil {
		t.Fatalf("DeleteWebAuthnCredential: %v", err)
	}
	list, _ = db.ListWebAuthnCredentials(ctx, u.ID)
	if len(list) != 0 {
		t.Errorf("after delete: want 0, got %d", len(list))
	}

	if _, err := db.GetWebAuthnCredentialByCredentialID(ctx, []byte{9, 9, 9}); err != store.ErrNotFound {
		t.Errorf("missing cred: want ErrNotFound, got %v", err)
	}
}

func TestWebAuthnSessionLifecycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, _ := newUserAndClient(t, db)

	sid, err := db.CreateWebAuthnSession(ctx, u.ID, []byte(`{"some":"data"}`), "register")
	if err != nil {
		t.Fatalf("CreateWebAuthnSession: %v", err)
	}

	data, err := db.GetWebAuthnSession(ctx, sid, u.ID, "register")
	if err != nil {
		t.Fatalf("GetWebAuthnSession: %v", err)
	}
	if string(data) != `{"some":"data"}` {
		t.Errorf("session data: got %s", data)
	}

	// Wrong purpose → ErrNotFound.
	if _, err := db.GetWebAuthnSession(ctx, sid, u.ID, "login"); err != store.ErrNotFound {
		t.Errorf("wrong purpose: want ErrNotFound, got %v", err)
	}

	// Wrong user → ErrNotFound.
	if _, err := db.GetWebAuthnSession(ctx, sid, uuid.New(), "register"); err != store.ErrNotFound {
		t.Errorf("wrong user: want ErrNotFound, got %v", err)
	}

	if err := db.DeleteWebAuthnSession(ctx, sid); err != nil {
		t.Fatalf("DeleteWebAuthnSession: %v", err)
	}
	if _, err := db.GetWebAuthnSession(ctx, sid, u.ID, "register"); err != store.ErrNotFound {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

// ── Signing keys ──────────────────────────────────────────────────────────────

func TestSigningKeyLifecycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if _, err := db.GetActiveSigningKey(ctx); err != store.ErrNotFound {
		t.Errorf("empty: want ErrNotFound, got %v", err)
	}

	k1 := &model.SigningKey{ID: uuid.New(), KID: "kid-1", Algorithm: "RS256", Active: true, EncryptedPrivateKey: []byte("p1"), EncryptedDEK: []byte("d1")}
	if err := db.CreateSigningKey(ctx, k1); err != nil {
		t.Fatalf("CreateSigningKey k1: %v", err)
	}

	got, err := db.GetActiveSigningKey(ctx)
	if err != nil {
		t.Fatalf("GetActiveSigningKey: %v", err)
	}
	if got.KID != "kid-1" {
		t.Errorf("KID: want kid-1, got %s", got.KID)
	}

	k2 := &model.SigningKey{ID: uuid.New(), KID: "kid-2", Algorithm: "RS256", Active: true, EncryptedPrivateKey: []byte("p2"), EncryptedDEK: []byte("d2")}
	if err := db.CreateSigningKey(ctx, k2); err != nil {
		t.Fatalf("CreateSigningKey k2: %v", err)
	}

	keys, err := db.ListActiveSigningKeys(ctx)
	if err != nil {
		t.Fatalf("ListActiveSigningKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("active count: want 2, got %d", len(keys))
	}

	if err := db.DeactivateSigningKey(ctx, k1.ID); err != nil {
		t.Fatalf("DeactivateSigningKey: %v", err)
	}
	keys, _ = db.ListActiveSigningKeys(ctx)
	if len(keys) != 1 || keys[0].KID != "kid-2" {
		t.Errorf("after deactivate k1: %v", keys)
	}

	// Active lookup now returns k2 unambiguously.
	got, _ = db.GetActiveSigningKey(ctx)
	if got.KID != "kid-2" {
		t.Errorf("GetActiveSigningKey after deactivate: want kid-2, got %s", got.KID)
	}
}

// ── Integrations ──────────────────────────────────────────────────────────────

func TestIntegrationLifecycle(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	i := &model.AppIntegration{
		Name:     "scim-vault",
		Provider: model.AppIntegrationProviderSCIM,
		Enabled:  true,
		Config: model.AppIntegrationConfig{
			BaseURL:   "https://vault.example/scim/v2",
			TimeoutMS: 5000,
			AuthMode:  model.AppIntegrationAuthBearer,
		},
		EncryptedToken: []byte("etok"),
		EncryptedDEK:   []byte("edek"),
	}
	if err := db.CreateIntegration(ctx, i); err != nil {
		t.Fatalf("CreateIntegration: %v", err)
	}
	if i.ID == uuid.Nil {
		t.Error("CreateIntegration should populate ID")
	}
	if i.CreatedAt.IsZero() || i.UpdatedAt.IsZero() {
		t.Error("CreateIntegration should populate timestamps")
	}

	got, err := db.GetIntegration(ctx, i.ID)
	if err != nil {
		t.Fatalf("GetIntegration: %v", err)
	}
	if got.Config.BaseURL != "https://vault.example/scim/v2" {
		t.Errorf("Config.BaseURL round-trip: got %q", got.Config.BaseURL)
	}
	if got.Config.AuthMode != model.AppIntegrationAuthBearer {
		t.Errorf("Config.AuthMode round-trip: got %q", got.Config.AuthMode)
	}

	byName, err := db.GetIntegrationByName(ctx, "scim-vault")
	if err != nil {
		t.Fatalf("GetIntegrationByName: %v", err)
	}
	if byName.ID != i.ID {
		t.Errorf("name lookup id mismatch")
	}

	// Duplicate name → ErrConflict.
	dup := &model.AppIntegration{Name: "scim-vault", Provider: "scim", Enabled: true}
	if err := db.CreateIntegration(ctx, dup); err != store.ErrConflict {
		t.Errorf("dup name: want ErrConflict, got %v", err)
	}

	// Disable + update.
	i.Enabled = false
	i.Config.TimeoutMS = 9000
	if err := db.UpdateIntegration(ctx, i); err != nil {
		t.Fatalf("UpdateIntegration: %v", err)
	}
	got, _ = db.GetIntegration(ctx, i.ID)
	if got.Enabled {
		t.Error("after disable: expected enabled=false")
	}
	if got.Config.TimeoutMS != 9000 {
		t.Errorf("TimeoutMS: want 9000, got %d", got.Config.TimeoutMS)
	}

	// List vs ListEnabled.
	all, _ := db.ListIntegrations(ctx)
	if len(all) != 1 {
		t.Errorf("ListIntegrations: want 1, got %d", len(all))
	}
	enabled, _ := db.ListEnabledIntegrations(ctx)
	if len(enabled) != 0 {
		t.Errorf("ListEnabledIntegrations: want 0 after disable, got %d", len(enabled))
	}

	if err := db.DeleteIntegration(ctx, i.ID); err != nil {
		t.Fatalf("DeleteIntegration: %v", err)
	}
	if err := db.DeleteIntegration(ctx, i.ID); err != store.ErrNotFound {
		t.Errorf("re-delete: want ErrNotFound, got %v", err)
	}
	if err := db.UpdateIntegration(ctx, i); err != store.ErrNotFound {
		t.Errorf("update missing: want ErrNotFound, got %v", err)
	}
	if _, err := db.GetIntegrationByName(ctx, "scim-vault"); err != store.ErrNotFound {
		t.Errorf("get-by-name missing: want ErrNotFound, got %v", err)
	}
}

// ── External IDs ──────────────────────────────────────────────────────────────

func TestExternalIDDelete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, _ := newUserAndClient(t, db)

	if err := db.SetExternalID(ctx, "iam", u.ID, "AIDABC123"); err != nil {
		t.Fatalf("SetExternalID: %v", err)
	}
	if err := db.DeleteExternalID(ctx, "iam", u.ID); err != nil {
		t.Fatalf("DeleteExternalID: %v", err)
	}
	if _, err := db.GetExternalID(ctx, "iam", u.ID); err != store.ErrNotFound {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

// ── Users — uncovered update paths ────────────────────────────────────────────

func TestUserUpdatePaths(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, _ := newUserAndClient(t, db)

	if err := db.UpdateUser(ctx, u.ID, "Renamed", false); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if err := db.UpdateUserPassword(ctx, u.ID, "new-hash"); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	if err := db.UpdateUserMFAEnabled(ctx, u.ID, true); err != nil {
		t.Fatalf("UpdateUserMFAEnabled: %v", err)
	}
	if err := db.SetUserActive(ctx, u.ID, false); err != nil {
		t.Fatalf("SetUserActive: %v", err)
	}
	if err := db.SetUserSCIMExternalID(ctx, u.ID, "scim-1"); err != nil {
		t.Fatalf("SetUserSCIMExternalID: %v", err)
	}
	if err := db.SetUserAdmin(ctx, u.ID, true); err != nil {
		t.Fatalf("SetUserAdmin: %v", err)
	}

	got, err := db.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Name != "Renamed" || got.Active || !got.MFAEnabled || !got.IsAdmin || got.SCIMExternalID != "scim-1" || got.PasswordHash != "new-hash" {
		t.Errorf("user updates didn't stick: %+v", got)
	}

	// Email lookup.
	got2, err := db.GetUserByEmail(ctx, got.Email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got2.ID != u.ID {
		t.Errorf("email lookup id mismatch")
	}

	// Count + list.
	if n, err := db.CountUsers(ctx); err != nil || n != 1 {
		t.Errorf("CountUsers: want (1, nil), got (%d, %v)", n, err)
	}
	list, err := db.ListUsers(ctx)
	if err != nil || len(list) != 1 {
		t.Errorf("ListUsers: want 1, got len=%d err=%v", len(list), err)
	}

	// Delete user (cascades sessions/grants/MFA via FKs).
	if err := db.DeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := db.GetUserByID(ctx, u.ID); err != store.ErrNotFound {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

// ── Clients — uncovered paths ─────────────────────────────────────────────────

func TestClientUpdateSecretAndDelete(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	_, c := newUserAndClient(t, db)

	if err := db.UpdateClientSecret(ctx, c.ID, "new-sec-hash"); err != nil {
		t.Fatalf("UpdateClientSecret: %v", err)
	}
	got, _ := db.GetClientByID(ctx, c.ID)
	if got.ClientSecretHash != "new-sec-hash" {
		t.Errorf("ClientSecretHash: want new-sec-hash, got %q", got.ClientSecretHash)
	}

	list, err := db.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(list) < 2 { // includes the seeded portal client
		t.Errorf("ListClients: want >= 2, got %d", len(list))
	}

	if err := db.DeleteClient(ctx, c.ID); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, err := db.GetClientByID(ctx, c.ID); err != store.ErrNotFound {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}

// ── Groups — uncovered paths ──────────────────────────────────────────────────

func TestGroupUpdateAndRemove(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	u, _ := newUserAndClient(t, db)

	g, err := db.CreateGroup(ctx, "eng")
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if err := db.AddGroupMember(ctx, g.ID, u.ID); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	if err := db.UpdateGroup(ctx, g.ID, "engineering"); err != nil {
		t.Fatalf("UpdateGroup: %v", err)
	}
	got, _ := db.GetGroupByID(ctx, g.ID)
	if got.DisplayName != "engineering" {
		t.Errorf("DisplayName: want engineering, got %q", got.DisplayName)
	}

	list, err := db.ListGroups(ctx)
	if err != nil || len(list) != 1 {
		t.Errorf("ListGroups: len=%d err=%v", len(list), err)
	}

	if err := db.RemoveGroupMember(ctx, g.ID, u.ID); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	got, _ = db.GetGroupByID(ctx, g.ID)
	if len(got.Members) != 0 {
		t.Errorf("after remove: %v", got.Members)
	}

	if err := db.DeleteGroup(ctx, g.ID); err != nil {
		t.Fatalf("DeleteGroup: %v", err)
	}
	if _, err := db.GetGroupByID(ctx, g.ID); err != store.ErrNotFound {
		t.Errorf("after delete: want ErrNotFound, got %v", err)
	}
}
