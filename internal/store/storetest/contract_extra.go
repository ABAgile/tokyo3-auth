package storetest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// raceN runs fn from n goroutines released together and returns the errors.
func raceN(n int, fn func() error) []error {
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		errs  = make([]error, n)
	)
	for i := range n {
		wg.Go(func() {
			<-start
			errs[i] = fn()
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// testGrantSingleUseUnderConcurrency: of N concurrent redemptions of one
// authorization code exactly one wins; the rest see ErrNotFound.
func testGrantSingleUseUnderConcurrency(t *testing.T, newStore Factory) {
	db := newStore(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)
	g := &model.Grant{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID, CodeHash: "race-code",
		Scopes: []string{"openid"}, RedirectURI: "https://app.example/cb",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := db.CreateGrant(ctx, g); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	var wins, losses atomic.Int32
	for _, err := range raceN(16, func() error { return db.MarkGrantUsed(ctx, g.ID) }) {
		switch {
		case err == nil:
			wins.Add(1)
		case errors.Is(err, store.ErrNotFound):
			losses.Add(1)
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins.Load() != 1 || losses.Load() != 15 {
		t.Fatalf("wins=%d losses=%d, want 1 and 15", wins.Load(), losses.Load())
	}
}

// testRefreshRotationUnderConcurrency: rotation is guarded by the previous
// refresh hash, so concurrent rotations from the same token have one winner,
// and the winner's access hash is the one that resolves.
func testRefreshRotationUnderConcurrency(t *testing.T, newStore Factory) {
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

	var seq atomic.Int32
	winner := make(chan int32, 16)
	errs := raceN(16, func() error {
		n := seq.Add(1)
		err := db.RotateRefreshToken(ctx, sess.ID, "rh-0",
			"ah-"+string(rune('a'+n)), "rh-"+string(rune('a'+n)),
			time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))
		if err == nil {
			winner <- n
		}
		return err
	})
	close(winner)
	var wins int
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, store.ErrNotFound):
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("rotation winners = %d, want 1", wins)
	}
	n := <-winner
	if _, err := db.GetSessionByAccessTokenHash(ctx, "ah-"+string(rune('a'+n))); err != nil {
		t.Errorf("winner's access hash must resolve: %v", err)
	}
	if _, err := db.GetSessionByRefreshTokenHash(ctx, "rh-0"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("old refresh hash must be gone, got %v", err)
	}
	if _, err := db.GetSessionByAccessTokenHash(ctx, "ah-0"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("old access hash must be gone, got %v", err)
	}
}

// testUserConflictsAndNotFound pins the error mapping handlers rely on:
// duplicate email → ErrConflict (case-sensitive per backend is NOT assumed),
// missing rows → ErrNotFound.
func testUserConflictsAndNotFound(t *testing.T, newStore Factory) {
	db := newStore(t)
	ctx := context.Background()

	if _, err := db.CreateUser(ctx, "dup@example.com", "h", "Dup"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := db.CreateUser(ctx, "dup@example.com", "h", "Dup2"); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate email: want ErrConflict, got %v", err)
	}
	if _, err := db.GetUserByID(ctx, uuid.New()); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetUserByID missing: want ErrNotFound, got %v", err)
	}
	if _, err := db.GetUserByEmail(ctx, "nobody@example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetUserByEmail missing: want ErrNotFound, got %v", err)
	}
	if _, err := db.GetClientByClientID(ctx, "nope"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetClientByClientID missing: want ErrNotFound, got %v", err)
	}
	if _, err := db.CreateClient(ctx, "cid-dup", "", "A", nil, nil, true, nil); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	if _, err := db.CreateClient(ctx, "cid-dup", "", "B", nil, nil, true, nil); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate client_id: want ErrConflict, got %v", err)
	}
}

// testDeviceGrantLifecycle covers RFC 8628 state transitions: each is a
// guarded UPDATE, so illegal transitions must report ErrNotFound.
func testDeviceGrantLifecycle(t *testing.T, newStore Factory) {
	db := newStore(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)

	mk := func(dev, usr string, exp time.Time) *model.DeviceGrant {
		g := &model.DeviceGrant{
			DeviceCodeHash: dev, UserCodeHash: usr, ClientID: c.ID,
			Scopes: []string{"openid", "profile"}, ExpiresAt: exp.UTC(),
		}
		if err := db.CreateDeviceGrant(ctx, g); err != nil {
			t.Fatalf("CreateDeviceGrant %s: %v", dev, err)
		}
		return g
	}
	g := mk("dev-1", "usr-1", time.Now().Add(10*time.Minute))
	if err := db.CreateDeviceGrant(ctx, &model.DeviceGrant{
		DeviceCodeHash: "dev-1", UserCodeHash: "usr-x", ClientID: c.ID, ExpiresAt: time.Now().Add(time.Minute),
	}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("duplicate device_code_hash: want ErrConflict, got %v", err)
	}

	got, err := db.GetDeviceGrantByDeviceCodeHash(ctx, "dev-1")
	if err != nil {
		t.Fatalf("GetByDeviceCodeHash: %v", err)
	}
	if got.Status != model.DeviceGrantStatusPending || got.IntervalSec != 5 || got.UserID != nil ||
		!sliceEq(got.Scopes, []string{"openid", "profile"}) {
		t.Errorf("fresh grant wrong: %+v", got)
	}
	if byUser, err := db.GetDeviceGrantByUserCodeHash(ctx, "usr-1"); err != nil || byUser.ID != g.ID {
		t.Errorf("GetByUserCodeHash: %v %+v", err, byUser)
	}

	// Redeem before approval is illegal.
	if err := db.MarkDeviceGrantRedeemed(ctx, g.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("redeem pending: want ErrNotFound, got %v", err)
	}

	polled := time.Now().UTC().Truncate(time.Second)
	if err := db.UpdateDeviceGrantPoll(ctx, g.ID, polled, 10); err != nil {
		t.Fatalf("UpdateDeviceGrantPoll: %v", err)
	}

	mfaAt := time.Now().UTC().Truncate(time.Second)
	if err := db.MarkDeviceGrantApproved(ctx, g.ID, u.ID, true, &mfaAt, "203.0.113.9"); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Approve and deny are only legal from pending.
	if err := db.MarkDeviceGrantApproved(ctx, g.ID, u.ID, false, nil, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("double approve: want ErrNotFound, got %v", err)
	}
	if err := db.MarkDeviceGrantDenied(ctx, g.ID, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deny approved: want ErrNotFound, got %v", err)
	}
	got, _ = db.GetDeviceGrantByDeviceCodeHash(ctx, "dev-1")
	if got.Status != model.DeviceGrantStatusApproved || got.UserID == nil || *got.UserID != u.ID ||
		!got.MFAVerified || got.MFAVerifiedAt == nil || !got.MFAVerifiedAt.Equal(mfaAt) ||
		got.ApproverIP != "203.0.113.9" || got.IntervalSec != 10 ||
		got.LastPolledAt == nil || !got.LastPolledAt.Equal(polled) {
		t.Errorf("approved grant wrong: %+v", got)
	}

	// Redemption is single-use, also under concurrency.
	var wins atomic.Int32
	for _, err := range raceN(8, func() error { return db.MarkDeviceGrantRedeemed(ctx, g.ID) }) {
		if err == nil {
			wins.Add(1)
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Errorf("unexpected redeem error: %v", err)
		}
	}
	if wins.Load() != 1 {
		t.Errorf("redeem winners = %d, want 1", wins.Load())
	}

	// Denial path.
	d := mk("dev-2", "usr-2", time.Now().Add(10*time.Minute))
	if err := db.MarkDeviceGrantDenied(ctx, d.ID, "198.51.100.1"); err != nil {
		t.Fatalf("deny: %v", err)
	}
	if err := db.MarkDeviceGrantApproved(ctx, d.ID, u.ID, false, nil, "x"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("approve denied: want ErrNotFound, got %v", err)
	}

	// Reaping removes only expired rows.
	mk("dev-3", "usr-3", time.Now().Add(-time.Minute))
	n, err := db.DeleteExpiredDeviceGrants(ctx)
	if err != nil || n != 1 {
		t.Errorf("DeleteExpiredDeviceGrants = %d, %v; want 1", n, err)
	}
	if _, err := db.GetDeviceGrantByDeviceCodeHash(ctx, "dev-3"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expired grant should be gone, got %v", err)
	}
	if _, err := db.GetDeviceGrantByDeviceCodeHash(ctx, "dev-2"); err != nil {
		t.Errorf("live grant must survive reap: %v", err)
	}
}

// testEmptyScopesRoundTrip: requests without a scope (e.g. client_credentials)
// produce nil scope slices; they must persist as empty arrays, not NULL.
func testEmptyScopesRoundTrip(t *testing.T, newStore Factory) {
	db := newStore(t)
	ctx := context.Background()
	u, c := newUserAndClient(t, db)

	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash: "ah-empty", RefreshTokenHash: "rh-empty",
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(2 * time.Hour),
	}
	if err := db.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession with nil scopes: %v", err)
	}
	if got, err := db.GetSessionByAccessTokenHash(ctx, "ah-empty"); err != nil || len(got.Scopes) != 0 {
		t.Errorf("session scopes = %v, %v; want empty", got, err)
	}

	g := &model.Grant{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID, CodeHash: "code-empty",
		RedirectURI: "https://app.example/cb", ExpiresAt: time.Now().Add(time.Minute).UTC(),
	}
	if err := db.CreateGrant(ctx, g); err != nil {
		t.Fatalf("CreateGrant with nil scopes: %v", err)
	}
	if got, err := db.GetGrantByCodeHash(ctx, "code-empty"); err != nil || len(got.Scopes) != 0 {
		t.Errorf("grant scopes = %v, %v; want empty", got, err)
	}

	noScopes, err := db.CreateClient(ctx, "no-scope-client", "", "No scopes", nil, nil, true, nil)
	if err != nil {
		t.Fatalf("CreateClient with nil arrays: %v", err)
	}
	if got, err := db.GetClientByID(ctx, noScopes.ID); err != nil || len(got.Scopes) != 0 || len(got.RedirectURIs) != 0 {
		t.Errorf("client arrays = %+v, %v; want empty", got, err)
	}
}
