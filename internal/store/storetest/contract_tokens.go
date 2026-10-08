package storetest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// testRetiredRefreshTokens: every refresh token a session rotates away from
// stays recognisable (so a replay can be detected) until the session goes.
func testRetiredRefreshTokens(t *testing.T, newStore Factory) {
	db := newStore(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)
	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash: "ah-0", RefreshTokenHash: "rh-0", Scopes: []string{"openid"},
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(2 * time.Hour),
	}
	if err := db.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	exp := func() (time.Time, time.Time) { return time.Now().Add(time.Hour), time.Now().Add(2 * time.Hour) }

	if _, err := db.GetSessionByRetiredRefreshTokenHash(ctx, "rh-0"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("live token must not look retired, got %v", err)
	}

	a, r := exp()
	if err := db.RotateRefreshToken(ctx, sess.ID, "rh-0", "ah-1", "rh-1", a, r); err != nil {
		t.Fatalf("rotate 1: %v", err)
	}
	a, r = exp()
	if err := db.RotateRefreshToken(ctx, sess.ID, "rh-1", "ah-2", "rh-2", a, r); err != nil {
		t.Fatalf("rotate 2: %v", err)
	}
	for _, old := range []string{"rh-0", "rh-1"} {
		got, err := db.GetSessionByRetiredRefreshTokenHash(ctx, old)
		if err != nil || got.ID != sess.ID {
			t.Errorf("retired %s: want session %s, got %v, %v", old, sess.ID, got, err)
		}
	}
	// The live token and unknown tokens are not "retired".
	for _, hash := range []string{"rh-2", "never-issued"} {
		if _, err := db.GetSessionByRetiredRefreshTokenHash(ctx, hash); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: want ErrNotFound, got %v", hash, err)
		}
	}
	// A failed (guarded) rotation must not record anything.
	a, r = exp()
	if err := db.RotateRefreshToken(ctx, sess.ID, "rh-0", "ah-x", "rh-x", a, r); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("replayed rotate: want ErrNotFound, got %v", err)
	}
	if _, err := db.GetSessionByRetiredRefreshTokenHash(ctx, "rh-x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("failed rotation recorded a retired token: %v", err)
	}

	// Retired tokens go with their session.
	if err := db.DeleteSession(ctx, sess.ID); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, err := db.GetSessionByRetiredRefreshTokenHash(ctx, "rh-0"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("retired token outlived its session: %v", err)
	}
}

// testAuthTimeRoundTrip: auth_time survives on grants and sessions; zero
// (unknown) stays zero rather than becoming a bogus timestamp.
func testAuthTimeRoundTrip(t *testing.T, newStore Factory) {
	db := newStore(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)
	at := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Second)

	for _, tc := range []struct {
		name string
		at   time.Time
	}{{"known", at}, {"unknown", time.Time{}}} {
		g := &model.Grant{
			ID: uuid.New(), UserID: u.ID, ClientID: c.ID, CodeHash: "code-" + tc.name,
			RedirectURI: "https://app.example/cb", ExpiresAt: time.Now().Add(time.Minute).UTC(),
			AuthTime: tc.at,
		}
		if err := db.CreateGrant(ctx, g); err != nil {
			t.Fatalf("%s: CreateGrant: %v", tc.name, err)
		}
		gg, err := db.GetGrantByCodeHash(ctx, "code-"+tc.name)
		if err != nil || !gg.AuthTime.Equal(tc.at) {
			t.Errorf("%s: grant AuthTime = %v, %v; want %v", tc.name, gg, err, tc.at)
		}

		sess := &model.Session{
			ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
			AccessTokenHash: "ah-" + tc.name, RefreshTokenHash: "rh-" + tc.name,
			AccessExpiresAt:  time.Now().Add(time.Hour),
			RefreshExpiresAt: time.Now().Add(2 * time.Hour),
			AuthTime:         tc.at,
		}
		if err := db.CreateSession(ctx, sess); err != nil {
			t.Fatalf("%s: CreateSession: %v", tc.name, err)
		}
		ss, err := db.GetSessionByAccessTokenHash(ctx, "ah-"+tc.name)
		if err != nil || !ss.AuthTime.Equal(tc.at) {
			t.Errorf("%s: session AuthTime = %v, %v; want %v", tc.name, ss, err, tc.at)
		}
	}
}
