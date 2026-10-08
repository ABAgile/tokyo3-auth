package api

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
	"github.com/abagile/tokyo3-auth/internal/model"
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/abagile/tokyo3-base/journal"
	"github.com/google/uuid"
)

func refreshForm(clientID, refresh string) string {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID}}.Encode()
}

// loginTokens runs a password login for a fresh user and returns the client
// and the token response.
func loginTokens(t *testing.T, r *testRig, email string) (*model.Client, map[string]any) {
	t.Helper()
	seedTestUser(t, r.store, email, "CorrectHorseB1!")
	c := seedPublicClient(t, r.store, "app-"+email, "https://app.example/cb", []string{"openid", "profile"})
	return c, runAuthCodeFlow(t, r, c.ClientID, "openid profile", email, "CorrectHorseB1!")
}

// Replaying a refresh token that was already rotated means it was copied:
// the session is revoked, so even the legitimately rotated tokens die.
func TestRefresh_ReplayRevokesSession(t *testing.T) {
	r := newTestRig(t)
	sink := &captureSink{}
	r.server.audit = journal.NewJSONSink[audit.Entry](sink)
	c, tok := loginTokens(t, r, "reuse@example.com")
	oldRefresh := tok["refresh_token"].(string)

	resp := r.postForm(t, "/token", refreshForm(c.ClientID, oldRefresh))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first refresh = %d", resp.StatusCode)
	}
	rotated := decodeJSON[map[string]any](t, resp)
	if got := bearerGet(t, r, "/userinfo", rotated["access_token"].(string)).StatusCode; got != http.StatusOK {
		t.Fatalf("rotated access token /userinfo = %d, want 200", got)
	}

	// The attacker replays the stolen (now retired) token.
	if got := r.postForm(t, "/token", refreshForm(c.ClientID, oldRefresh)).StatusCode; got != http.StatusBadRequest {
		t.Fatalf("replay = %d, want 400", got)
	}
	// ...which revoked the session: the legitimate pair is dead too.
	if got := bearerGet(t, r, "/userinfo", rotated["access_token"].(string)).StatusCode; got != http.StatusUnauthorized {
		t.Errorf("access token after reuse = %d, want 401", got)
	}
	if got := r.postForm(t, "/token", refreshForm(c.ClientID, rotated["refresh_token"].(string))).StatusCode; got != http.StatusBadRequest {
		t.Errorf("rotated refresh token after reuse = %d, want 400", got)
	}

	var found bool
	for _, p := range sink.rows {
		var e audit.Entry
		if err := json.Unmarshal(p, &e); err != nil {
			t.Fatal(err)
		}
		found = found || e.Action == ActionTokenReuseDetected
	}
	if !found {
		t.Errorf("no %s audit event recorded", ActionTokenReuseDetected)
	}
}

// Unknown tokens, and another client replaying someone's retired token, get a
// plain invalid_grant and never revoke anything.
func TestRefresh_UnknownOrForeignReplayDoesNotRevoke(t *testing.T) {
	r := newTestRig(t)
	c, tok := loginTokens(t, r, "foreign@example.com")
	oldRefresh := tok["refresh_token"].(string)
	rotated := decodeJSON[map[string]any](t, r.postForm(t, "/token", refreshForm(c.ClientID, oldRefresh)))

	other := seedPublicClient(t, r.store, "other", "https://other.example/cb", []string{"openid"})
	if got := r.postForm(t, "/token", refreshForm(other.ClientID, oldRefresh)).StatusCode; got != http.StatusBadRequest {
		t.Errorf("foreign replay = %d, want 400", got)
	}
	if got := r.postForm(t, "/token", refreshForm(c.ClientID, "never-issued")).StatusCode; got != http.StatusBadRequest {
		t.Errorf("unknown token = %d, want 400", got)
	}
	if got := bearerGet(t, r, "/userinfo", rotated["access_token"].(string)).StatusCode; got != http.StatusOK {
		t.Errorf("session must survive: /userinfo = %d, want 200", got)
	}
	if got := r.postForm(t, "/token", refreshForm(c.ClientID, rotated["refresh_token"].(string))).StatusCode; got != http.StatusOK {
		t.Errorf("legitimate refresh after foreign replay = %d, want 200", got)
	}
}

// The same token presented concurrently: one winner, everyone else is treated
// as a replay, and the session ends up revoked.
func TestRefresh_ConcurrentUseSingleWinnerThenRevoked(t *testing.T) {
	r := newTestRig(t)
	c, tok := loginTokens(t, r, "concurrent@example.com")
	form := refreshForm(c.ClientID, tok["refresh_token"].(string))

	const n = 8
	var (
		mu     sync.Mutex
		wins   int
		access string
		wg     sync.WaitGroup
	)
	for range n {
		wg.Go(func() {
			resp, err := http.Post(r.srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form))
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			var out map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&out)
			mu.Lock()
			wins++
			access, _ = out["access_token"].(string)
			mu.Unlock()
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("successful refreshes = %d, want exactly 1", wins)
	}
	if got := bearerGet(t, r, "/userinfo", access).StatusCode; got != http.StatusUnauthorized {
		t.Errorf("winner's access token after losers replayed = %d, want 401 (session revoked)", got)
	}
}

func claimAuthTime(t *testing.T, tok map[string]any) time.Time {
	t.Helper()
	claims := decodeJWTPayload(t, tok["id_token"].(string))
	f, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time missing from id_token: %v", claims)
	}
	return time.Unix(int64(f), 0)
}

// auth_time is when the user authenticated, not when the token was minted,
// and a refreshed ID token keeps the original value.
func TestIDToken_AuthTimeIsLoginTimeAndSurvivesRefresh(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	u := seedTestUser(t, r.store, "authtime@example.com", "CorrectHorseB1!")
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})
	verifier, challenge := pkcePair("verifier-1234567890123456789012345678901234567890")

	loggedInAt := time.Now().Add(-45 * time.Minute).UTC().Truncate(time.Second)
	if err := r.store.CreateGrant(ctx, &model.Grant{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID, CodeHash: creds.HashToken("old-login"),
		CodeChallenge: challenge, Scopes: []string{"openid"}, RedirectURI: "https://app.example/cb",
		ExpiresAt: time.Now().Add(time.Minute), AuthTime: loggedInAt,
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"old-login"}, "code_verifier": {verifier},
		"redirect_uri": {"https://app.example/cb"}, "client_id": {c.ClientID},
	}
	tok := decodeJSON[map[string]any](t, r.postForm(t, "/token", form.Encode()))
	if got := claimAuthTime(t, tok); !got.Equal(loggedInAt) {
		t.Errorf("auth_time = %v, want login time %v", got, loggedInAt)
	}

	refreshed := decodeJSON[map[string]any](t, r.postForm(t, "/token", refreshForm(c.ClientID, tok["refresh_token"].(string))))
	if got := claimAuthTime(t, refreshed); !got.Equal(loggedInAt) {
		t.Errorf("refreshed auth_time = %v, want original %v", got, loggedInAt)
	}
}

// A fresh password login reports roughly "now".
func TestIDToken_AuthTimeForFreshLogin(t *testing.T) {
	r := newTestRig(t)
	_, tok := loginTokens(t, r, "fresh@example.com")
	if d := math.Abs(time.Since(claimAuthTime(t, tok)).Seconds()); d > 30 {
		t.Errorf("auth_time off by %.0fs for a fresh login", d)
	}
}
