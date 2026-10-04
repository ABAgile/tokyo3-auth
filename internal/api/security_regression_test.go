package api

import (
	"context"
	"errors"
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

// authorizePOST submits the login form and returns the response.
func authorizePOST(t *testing.T, r *testRig, clientID, scope, email, password string) *http.Response {
	t.Helper()
	_, challenge := pkcePair("verifier-1234567890123456789012345678901234567890")
	form := url.Values{
		"client_id":      {clientID},
		"redirect_uri":   {"https://app.example/cb"},
		"scope":          {scope},
		"state":          {"s"},
		"code_challenge": {challenge},
		"email":          {email},
		"password":       {password},
	}
	return r.postForm(t, "/authorize", form.Encode())
}

func bearerGet(t *testing.T, r *testRig, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

// A client must not be able to obtain scopes it isn't registered for.
func TestAuthorizePOST_RejectsUnregisteredScope(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "mallory@example.com", "CorrectHorseB1!")
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})

	resp := authorizePOST(t, r, c.ClientID, "openid admin", "mallory@example.com", "CorrectHorseB1!")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 invalid_scope", resp.StatusCode)
	}
}

func TestAuthorizeGET_RejectsUnregisteredScope(t *testing.T) {
	r := newTestRig(t)
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})
	q := url.Values{
		"client_id": {c.ClientID}, "redirect_uri": {"https://app.example/cb"},
		"scope": {"openid admin"}, "state": {"xyz"},
	}
	resp := r.get(t, "/authorize?"+q.Encode())
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "invalid_scope" {
		t.Fatalf("status=%d location=%v, want redirect with error=invalid_scope", resp.StatusCode, loc)
	}
}

func TestClientCredentials_RejectsUnregisteredScope(t *testing.T) {
	r := newTestRig(t)
	seedTestClient(t, r.store, "svc", "https://x/cb", "sec", []string{"openid"})
	body := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc-cid"},
		"client_secret": {"sec"}, "scope": {"admin"},
	}
	resp := r.postForm(t, "/token", body.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

// A session carrying the "admin" scope string is not enough: the owning user
// must be an active admin.
func TestAdminAuth_RequiresAdminUser(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	tok := seedAdminSession(t, r) // admin user, scope admin
	if resp := adminReq(t, r, "GET", "/admin/users", "", tok); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin baseline status = %d, want 200", resp.StatusCode)
	}

	u, err := r.store.GetUserByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if err := r.store.SetUserAdmin(ctx, u.ID, false); err != nil {
		t.Fatalf("SetUserAdmin: %v", err)
	}
	if resp := adminReq(t, r, "GET", "/admin/users", "", tok); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("demoted admin status = %d, want 403", resp.StatusCode)
	}
}

// Password-only login must not be reported as MFA-verified.
func TestCodeExchange_PasswordOnlyIsNotMFAVerified(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "pw@example.com", "CorrectHorseB1!")
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})

	tok := runAuthCodeFlow(t, r, c.ClientID, "openid", "pw@example.com", "CorrectHorseB1!")
	access, _ := tok["access_token"].(string)
	sess, err := r.store.GetSessionByAccessTokenHash(context.Background(), creds.HashToken(access))
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if sess.MFAVerified || sess.MFAVerifiedAt != nil {
		t.Errorf("password-only session marked MFA verified: %+v", sess)
	}
	claims := decodeJWTPayload(t, tok["id_token"].(string))
	if _, ok := claims["acr"]; ok {
		t.Errorf("acr present for password-only login: %v", claims["acr"])
	}
}

// A grant that records an MFA challenge yields an MFA-verified session.
func TestCodeExchange_CarriesGrantMFA(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	u := seedTestUser(t, r.store, "mfa@example.com", "CorrectHorseB1!")
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})
	verifier, challenge := pkcePair("verifier-1234567890123456789012345678901234567890")
	mfaAt := time.Now().UTC()
	if err := r.store.CreateGrant(ctx, &model.Grant{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID, CodeHash: creds.HashToken("the-code"),
		CodeChallenge: challenge, Scopes: []string{"openid"}, RedirectURI: "https://app.example/cb",
		ExpiresAt: time.Now().Add(time.Minute), MFAVerifiedAt: &mfaAt,
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"the-code"}, "code_verifier": {verifier},
		"redirect_uri": {"https://app.example/cb"}, "client_id": {c.ClientID},
	}
	tok := decodeJSON[map[string]any](t, r.postForm(t, "/token", form.Encode()))
	sess, err := r.store.GetSessionByAccessTokenHash(ctx, creds.HashToken(tok["access_token"].(string)))
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if !sess.MFAVerified || sess.MFAVerifiedAt == nil {
		t.Errorf("session should be MFA verified: %+v", sess)
	}
}

// Concurrent redemptions of one code: exactly one wins.
func TestCodeExchange_ConcurrentRedemptionSingleWinner(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	u := seedTestUser(t, r.store, "race@example.com", "CorrectHorseB1!")
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid"})
	verifier, challenge := pkcePair("verifier-1234567890123456789012345678901234567890")
	if err := r.store.CreateGrant(ctx, &model.Grant{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID, CodeHash: creds.HashToken("race-code"),
		CodeChallenge: challenge, Scopes: []string{"openid"}, RedirectURI: "https://app.example/cb",
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"race-code"}, "code_verifier": {verifier},
		"redirect_uri": {"https://app.example/cb"}, "client_id": {c.ClientID},
	}.Encode()

	const n = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range n {
		wg.Go(func() {
			resp, err := http.Post(r.srv.URL+"/token", "application/x-www-form-urlencoded", strings.NewReader(form))
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("successful redemptions = %d, want exactly 1", ok)
	}
}

// A refreshed access token must be usable, the old one retired, and the old
// refresh token unusable.
func TestRefresh_NewAccessTokenWorks(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "ref@example.com", "CorrectHorseB1!")
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid", "profile"})
	tok := runAuthCodeFlow(t, r, c.ClientID, "openid profile", "ref@example.com", "CorrectHorseB1!")
	oldAccess, oldRefresh := tok["access_token"].(string), tok["refresh_token"].(string)

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {oldRefresh}, "client_id": {c.ClientID}}.Encode()
	resp := r.postForm(t, "/token", form)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d", resp.StatusCode)
	}
	out := decodeJSON[map[string]any](t, resp)
	newAccess := out["access_token"].(string)

	if got := bearerGet(t, r, "/userinfo", newAccess).StatusCode; got != http.StatusOK {
		t.Errorf("new access token /userinfo = %d, want 200", got)
	}
	if got := bearerGet(t, r, "/userinfo", oldAccess).StatusCode; got != http.StatusUnauthorized {
		t.Errorf("old access token /userinfo = %d, want 401", got)
	}
	if got := r.postForm(t, "/token", form).StatusCode; got != http.StatusBadRequest {
		t.Errorf("replayed refresh token = %d, want 400", got)
	}
}

type failingSink struct{}

func (failingSink) Append(context.Context, []byte) error { return errors.New("journal down") }
func (failingSink) Close() error                         { return nil }

// With the journal down, admin mutations must be refused (503) and must not
// perform the destructive/privileged change.
func TestAdmin_AuditFailureFailsClosed(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	tok := seedAdminSession(t, r)
	victim := seedTestUser(t, r.store, "victim@example.com", "CorrectHorseB1!")
	r.server.audit = journal.NewJSONSink[audit.Entry](failingSink{})

	resp := adminReq(t, r, "POST", "/admin/users",
		`{"email":"new@x.com","password":"SuperLongP@ss12","name":"New"}`, tok)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("create status = %d, want 503", resp.StatusCode)
	}

	resp = adminReq(t, r, "DELETE", "/admin/users/"+victim.ID.String(), "", tok)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("delete status = %d, want 503", resp.StatusCode)
	}
	if _, err := r.store.GetUserByID(ctx, victim.ID); err != nil {
		t.Errorf("user must survive a refused delete: %v", err)
	}

	resp = adminReq(t, r, "PUT", "/admin/users/"+victim.ID.String(), `{"active":false}`, tok)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("update status = %d, want 503", resp.StatusCode)
	}
	if got, _ := r.store.GetUserByID(ctx, victim.ID); got == nil || !got.Active {
		t.Error("user must stay active after a refused deactivation")
	}
}
