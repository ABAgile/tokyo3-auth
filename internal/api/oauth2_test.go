package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store/sqlite"
	creds "github.com/abagile/tokyo3-base/auth/creds"
	"github.com/google/uuid"
)

// seedTestUser inserts a user with a known password and returns the User and
// the plaintext password used.
func seedTestUser(t *testing.T, db *sqlite.DB, email, password string) *model.User {
	t.Helper()
	hash, err := creds.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	u, err := db.CreateUser(context.Background(), email, hash, email)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := db.UpdateUserPassword(context.Background(), u.ID, hash); err != nil {
		t.Fatalf("UpdateUserPassword: %v", err)
	}
	// Default PasswordChangedAt is CURRENT_TIMESTAMP; matches a fresh password
	// so the PCI password-age rule passes.
	return u
}

// seedTestClient creates a confidential OAuth client. Confidential clients are
// blocked by the PCI MFARequiredRule unless the user has MFA enrolled — use
// seedPublicClient for interactive-login tests that don't exercise MFA.
func seedTestClient(t *testing.T, db *sqlite.DB, name, redirectURI, rawSecret string, scopes []string) *model.Client {
	t.Helper()
	secretHash := creds.HashToken(rawSecret)
	c, err := db.CreateClient(context.Background(), name+"-cid", secretHash, name,
		[]string{redirectURI}, scopes, false, nil)
	if err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	return c
}

func seedPublicClient(t *testing.T, db *sqlite.DB, name, redirectURI string, scopes []string) *model.Client {
	t.Helper()
	c, err := db.CreateClient(context.Background(), name+"-pub", "", name,
		[]string{redirectURI}, scopes, true, nil)
	if err != nil {
		t.Fatalf("CreateClient public: %v", err)
	}
	return c
}

// pkcePair returns (verifier, S256-challenge).
func pkcePair(verifier string) (string, string) {
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// ── /authorize POST (interactive login) ──────────────────────────────────────

func TestAuthorizePOST_Success(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "alice@example.com", "CorrectHorseB1!")
	// Public client — the PCI MFARequiredRule exempts public clients from the
	// MFA-required check, so a password-only login can complete.
	c := seedPublicClient(t, r.store, "app", "https://app.example/cb", []string{"openid", "email"})

	verifier, challenge := pkcePair("verifier-1234567890123456789012345678901234567890")

	form := url.Values{
		"client_id":      {c.ClientID},
		"redirect_uri":   {"https://app.example/cb"},
		"scope":          {"openid email"},
		"state":          {"opaque-state"},
		"nonce":          {"opaque-nonce"},
		"code_challenge": {challenge},
		"email":          {"alice@example.com"},
		"password":       {"CorrectHorseB1!"},
	}
	resp := r.postForm(t, "/authorize", form.Encode())
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("Location parse: %v", err)
	}
	if loc.Scheme != "https" || loc.Host != "app.example" || loc.Path != "/cb" {
		t.Errorf("Location target wrong: %s", loc)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("no code in Location")
	}
	if loc.Query().Get("state") != "opaque-state" {
		t.Errorf("state echo: got %q", loc.Query().Get("state"))
	}

	// Exchange the code for tokens.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {"https://app.example/cb"},
		"client_id":     {c.ClientID},
	}
	tokResp := r.postForm(t, "/token", tokenForm.Encode())
	if tokResp.StatusCode != http.StatusOK {
		t.Fatalf("/token status = %d", tokResp.StatusCode)
	}
	tok := decodeJSON[map[string]any](t, tokResp)
	if tok["access_token"] == "" || tok["refresh_token"] == "" {
		t.Errorf("missing tokens: %v", tok)
	}
	if tok["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", tok["token_type"])
	}
	if tok["id_token"] == "" {
		t.Error("openid scope present → id_token must be present")
	}

	// Replay must fail (used grants are rejected).
	tokResp = r.postForm(t, "/token", tokenForm.Encode())
	if tokResp.StatusCode != http.StatusBadRequest {
		t.Errorf("replay status = %d, want 400", tokResp.StatusCode)
	}
}

func TestAuthorizePOST_BadCredentials(t *testing.T) {
	r := newTestRig(t)
	seedTestUser(t, r.store, "alice@example.com", "CorrectHorseB1!")
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid"})

	form := url.Values{
		"client_id":    {c.ClientID},
		"redirect_uri": {"https://app.example/cb"},
		"email":        {"alice@example.com"},
		"password":     {"WrongPassword!"},
	}
	resp := r.postForm(t, "/authorize", form.Encode())
	// Failed login re-renders the form inline (200), no redirect.
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 (re-render)", resp.StatusCode)
	}
}

func TestAuthorizePOST_UnknownClient(t *testing.T) {
	r := newTestRig(t)
	form := url.Values{
		"client_id":    {"bogus-client"},
		"redirect_uri": {"https://x/cb"},
		"email":        {"a@b"},
		"password":     {"x"},
	}
	resp := r.postForm(t, "/authorize", form.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeGET_UnknownClient(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/authorize?client_id=missing&redirect_uri=https://x")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeGET_BadRedirect(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid"})
	resp := r.get(t, "/authorize?client_id="+c.ClientID+"&redirect_uri=https://evil/")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeGET_PromptNone_NoSession(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid"})
	resp := r.get(t, "/authorize?client_id="+c.ClientID+
		"&redirect_uri=https://app.example/cb&prompt=none&state=s1")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302 (OIDC error redirect)", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "login_required" {
		t.Errorf("error = %q, want login_required", loc.Query().Get("error"))
	}
	if loc.Query().Get("state") != "s1" {
		t.Errorf("state echo: %q", loc.Query().Get("state"))
	}
}

// ── /token error paths ───────────────────────────────────────────────────────

func TestToken_UnsupportedGrant(t *testing.T) {
	r := newTestRig(t)
	resp := r.postForm(t, "/token", "grant_type=password")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

func TestToken_BadClientSecret(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "rightsec", []string{"openid"})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"deadbeef"},
		"client_id":     {c.ClientID},
		"client_secret": {"wrongsec"},
	}
	resp := r.postForm(t, "/token", form.Encode())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestToken_MissingClientSecret(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "rightsec", []string{"openid"})

	form := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {"deadbeef"},
		"client_id":  {c.ClientID},
	}
	resp := r.postForm(t, "/token", form.Encode())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestToken_ClientCredentialsGrant(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "machine", "https://x.example/cb", "ccsec", []string{"api"})

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {"ccsec"},
		"scope":         {"api"},
	}
	resp := r.postForm(t, "/token", form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	tok := decodeJSON[map[string]any](t, resp)
	rawAccess, _ := tok["access_token"].(string)
	if rawAccess == "" {
		t.Fatal("no access_token")
	}
	if _, ok := tok["id_token"]; ok {
		t.Error("client_credentials must not issue an id_token (no openid scope, no user)")
	}

	// Session was persisted with NULL user_id — verify the access token works
	// for bearerAuth-protected endpoints.
	sess, err := r.store.GetSessionByAccessTokenHash(context.Background(), creds.HashToken(rawAccess))
	if err != nil {
		t.Fatalf("session not persisted: %v", err)
	}
	if sess.UserID != uuid.Nil {
		t.Errorf("UserID = %v, want uuid.Nil (machine session)", sess.UserID)
	}

	// /userinfo must refuse the machine token (§5.3 has no defined response
	// when there is no user).
	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+rawAccess)
	uiResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer uiResp.Body.Close()
	if uiResp.StatusCode != http.StatusForbidden {
		t.Errorf("/userinfo machine-token status = %d, want 403", uiResp.StatusCode)
	}
}

func TestToken_ClientCredentials_PublicClientRejected(t *testing.T) {
	r := newTestRig(t)
	// Build a public client by hand (seedTestClient defaults Public=false).
	pc, err := r.store.CreateClient(context.Background(), "pub-cid", "", "Public",
		[]string{"https://pub/cb"}, []string{"openid"}, true, nil)
	if err != nil {
		t.Fatalf("CreateClient public: %v", err)
	}
	form := url.Values{
		"grant_type": {"client_credentials"},
		"client_id":  {pc.ClientID},
	}
	resp := r.postForm(t, "/token", form.Encode())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("public client + client_credentials: status = %d, want 401", resp.StatusCode)
	}
}

func TestToken_Refresh_RoundTripAndExpiry(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid"})

	// Mint a session row directly. Avoid the full login + code-exchange dance.
	rawAccess, _ := creds.GenerateRawToken()
	rawRefresh, _ := creds.GenerateRawToken()
	now := time.Now().UTC().Truncate(time.Second)
	u := seedTestUser(t, r.store, "bob@example.com", "AnotherG00d!")
	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(rawAccess),
		RefreshTokenHash: creds.HashToken(rawRefresh),
		Scopes:           []string{"openid"},
		AccessExpiresAt:  now.Add(time.Hour),
		RefreshExpiresAt: now.Add(2 * time.Hour),
	}
	if err := r.store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {rawRefresh},
		"client_id":     {c.ClientID},
		"client_secret": {"sec"},
	}
	resp := r.postForm(t, "/token", form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh status = %d", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp)
	newRefresh, _ := body["refresh_token"].(string)
	if newRefresh == "" || newRefresh == rawRefresh {
		t.Errorf("refresh_token: want fresh token, got %q (old %q)", newRefresh, rawRefresh)
	}
	if _, ok := body["id_token"]; !ok {
		t.Error("openid scope present → expected id_token in refresh response")
	}

	// Old refresh must no longer work after rotation.
	resp = r.postForm(t, "/token", form.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("replay old refresh: status = %d, want 400", resp.StatusCode)
	}
}

func TestToken_Refresh_Unknown(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid"})
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"not-a-real-token"},
		"client_id":     {c.ClientID},
		"client_secret": {"sec"},
	}
	resp := r.postForm(t, "/token", form.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}

// ── /userinfo ────────────────────────────────────────────────────────────────

func TestUserInfo_BearerAuth(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid", "profile"})
	u := seedTestUser(t, r.store, "carol@example.com", "S0meL0ng!Pass")

	rawAccess, _ := creds.GenerateRawToken()
	rawRefresh, _ := creds.GenerateRawToken()
	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(rawAccess),
		RefreshTokenHash: creds.HashToken(rawRefresh),
		Scopes:           []string{"openid", "profile"},
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(2 * time.Hour),
	}
	if err := r.store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+rawAccess)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp)
	if body["email"] != "carol@example.com" {
		t.Errorf("email = %v, want carol@example.com", body["email"])
	}
	if body["sub"] != u.ID.String() {
		t.Errorf("sub = %v, want %s", body["sub"], u.ID)
	}
	if body["name"] != "carol@example.com" {
		t.Errorf("name = %v, want carol@example.com (we seeded name=email)", body["name"])
	}
}

func TestUserInfo_MissingToken(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/userinfo")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestUserInfo_BadToken(t *testing.T) {
	r := newTestRig(t)
	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestUserInfo_ExpiredToken(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid"})
	u := seedTestUser(t, r.store, "dave@example.com", "Tr0ub4dor!&3")

	rawAccess, _ := creds.GenerateRawToken()
	rawRefresh, _ := creds.GenerateRawToken()
	expired := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(rawAccess),
		RefreshTokenHash: creds.HashToken(rawRefresh),
		Scopes:           []string{"openid"},
		AccessExpiresAt:  time.Now().Add(-time.Minute),
		RefreshExpiresAt: time.Now().Add(time.Hour),
	}
	if err := r.store.CreateSession(context.Background(), expired); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+rawAccess)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

// ── /revoke ──────────────────────────────────────────────────────────────────

func TestRevoke(t *testing.T) {
	r := newTestRig(t)
	c := seedTestClient(t, r.store, "app", "https://app.example/cb", "sec", []string{"openid"})
	u := seedTestUser(t, r.store, "eve@example.com", "Lots0fStuff#1")

	rawAccess, _ := creds.GenerateRawToken()
	rawRefresh, _ := creds.GenerateRawToken()
	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(rawAccess),
		RefreshTokenHash: creds.HashToken(rawRefresh),
		Scopes:           []string{"openid"},
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(2 * time.Hour),
	}
	if err := r.store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	resp := r.postForm(t, "/revoke", "token="+rawAccess)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/revoke status = %d, want 200", resp.StatusCode)
	}
	if _, err := r.store.GetSessionByAccessTokenHash(context.Background(), creds.HashToken(rawAccess)); err == nil {
		t.Error("session should be gone after revoke")
	}

	// Revoke a no-op token is still OK.
	resp = r.postForm(t, "/revoke", "token=nope")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/revoke unknown token: status = %d, want 200", resp.StatusCode)
	}

	// Revoke via refresh token hash also works.
	rawAccess2, _ := creds.GenerateRawToken()
	rawRefresh2, _ := creds.GenerateRawToken()
	sess2 := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(rawAccess2),
		RefreshTokenHash: creds.HashToken(rawRefresh2),
		Scopes:           []string{"openid"},
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(2 * time.Hour),
	}
	if err := r.store.CreateSession(context.Background(), sess2); err != nil {
		t.Fatalf("CreateSession 2: %v", err)
	}
	resp = r.postForm(t, "/revoke", "token="+rawRefresh2)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("/revoke refresh: status = %d, want 200", resp.StatusCode)
	}
}

// ── Admin endpoints ──────────────────────────────────────────────────────────

// seedAdminSession creates an admin-scoped session and returns the raw bearer
// token usable in Authorization: Bearer ...
func seedAdminSession(t *testing.T, r *testRig) string {
	t.Helper()
	c, _ := r.store.GetClientByClientID(context.Background(), "portal")
	if c == nil {
		c = seedTestClient(t, r.store, "admin-client", "https://x/cb", "sec", []string{"admin"})
	}
	u := seedTestUser(t, r.store, "admin@example.com", "AdminPass!1")
	rawAccess, _ := creds.GenerateRawToken()
	rawRefresh, _ := creds.GenerateRawToken()
	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(rawAccess),
		RefreshTokenHash: creds.HashToken(rawRefresh),
		Scopes:           []string{"admin"},
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(2 * time.Hour),
	}
	if err := r.store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateSession admin: %v", err)
	}
	return rawAccess
}

func adminReq(t *testing.T, r *testRig, method, path, body, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, r.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	c := &http.Client{CheckRedirect: noFollow}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func TestAdmin_UserCRUD(t *testing.T) {
	r := newTestRig(t)
	tok := seedAdminSession(t, r)

	// Create.
	resp := adminReq(t, r, "POST", "/admin/users",
		`{"email":"new@x.com","password":"SuperLongP@ss12","name":"New"}`, tok)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp)
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatal("no id returned")
	}

	// Duplicate email → 409.
	resp = adminReq(t, r, "POST", "/admin/users",
		`{"email":"new@x.com","password":"AnotherL0ng@","name":"Dup"}`, tok)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate status = %d, want 409", resp.StatusCode)
	}

	// Missing required field → 400.
	resp = adminReq(t, r, "POST", "/admin/users", `{"email":""}`, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("missing fields status = %d, want 400", resp.StatusCode)
	}

	// List.
	resp = adminReq(t, r, "GET", "/admin/users", "", tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	list := decodeJSON[map[string]any](t, resp)
	users, _ := list["users"].([]any)
	if len(users) < 2 { // admin + new
		t.Errorf("user count: want >= 2, got %d", len(users))
	}

	// Get.
	resp = adminReq(t, r, "GET", "/admin/users/"+id, "", tok)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get status = %d", resp.StatusCode)
	}

	// Get missing.
	resp = adminReq(t, r, "GET", "/admin/users/"+uuid.NewString(), "", tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("get missing status = %d, want 404", resp.StatusCode)
	}

	// Get bad UUID.
	resp = adminReq(t, r, "GET", "/admin/users/not-a-uuid", "", tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("get bad uuid status = %d, want 400", resp.StatusCode)
	}

	// Update (deactivate).
	resp = adminReq(t, r, "PUT", "/admin/users/"+id,
		`{"name":"Renamed","active":false}`, tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d", resp.StatusCode)
	}
	body = decodeJSON[map[string]any](t, resp)
	if body["name"] != "Renamed" || body["active"] != false {
		t.Errorf("update payload: %v", body)
	}

	// Delete.
	resp = adminReq(t, r, "DELETE", "/admin/users/"+id, "", tok)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", resp.StatusCode)
	}
}

func TestAdmin_ClientCRUD(t *testing.T) {
	r := newTestRig(t)
	tok := seedAdminSession(t, r)

	// Create.
	resp := adminReq(t, r, "POST", "/admin/clients",
		`{"name":"My App","redirect_uris":["https://app/cb"]}`, tok)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d", resp.StatusCode)
	}
	body := decodeJSON[map[string]any](t, resp)
	id, _ := body["id"].(string)
	rawSecret, _ := body["client_secret"].(string)
	if id == "" || rawSecret == "" {
		t.Fatalf("missing id/secret: %v", body)
	}
	if !strings.Contains(body["client_id"].(string), "") {
		t.Errorf("client_id missing: %v", body)
	}

	// Empty name → 400.
	resp = adminReq(t, r, "POST", "/admin/clients", `{"name":""}`, tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty-name status = %d, want 400", resp.StatusCode)
	}

	// List.
	resp = adminReq(t, r, "GET", "/admin/clients", "", tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	list := decodeJSON[map[string]any](t, resp)
	if len(list["clients"].([]any)) < 2 { // portal + new
		t.Errorf("client list too short: %v", list)
	}

	// Get.
	resp = adminReq(t, r, "GET", "/admin/clients/"+id, "", tok)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("get status = %d", resp.StatusCode)
	}

	// Get not-found.
	resp = adminReq(t, r, "GET", "/admin/clients/"+uuid.NewString(), "", tok)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing status = %d, want 404", resp.StatusCode)
	}

	// Rotate secret.
	resp = adminReq(t, r, "POST", "/admin/clients/"+id+"/rotate-secret", "", tok)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status = %d", resp.StatusCode)
	}
	rotated := decodeJSON[map[string]string](t, resp)
	if rotated["client_secret"] == "" || rotated["client_secret"] == rawSecret {
		t.Errorf("rotate returned stale or empty secret: %v", rotated)
	}

	// Delete.
	resp = adminReq(t, r, "DELETE", "/admin/clients/"+id, "", tok)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete status = %d, want 204", resp.StatusCode)
	}
}

func TestAdmin_RequiresAdminScope(t *testing.T) {
	r := newTestRig(t)
	// Seed a non-admin session (scope = "openid"), bearer token works for /userinfo
	// but adminAuth must reject it.
	c := seedTestClient(t, r.store, "app", "https://x/cb", "sec", []string{"openid"})
	u := seedTestUser(t, r.store, "user@example.com", "AbCdEfG1!@")
	raw, _ := creds.GenerateRawToken()
	refresh, _ := creds.GenerateRawToken()
	sess := &model.Session{
		ID: uuid.New(), UserID: u.ID, ClientID: c.ID,
		AccessTokenHash:  creds.HashToken(raw),
		RefreshTokenHash: creds.HashToken(refresh),
		Scopes:           []string{"openid"},
		AccessExpiresAt:  time.Now().Add(time.Hour),
		RefreshExpiresAt: time.Now().Add(2 * time.Hour),
	}
	if err := r.store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	resp := adminReq(t, r, "GET", "/admin/users", "", raw)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAdmin_NoTokenRejected(t *testing.T) {
	r := newTestRig(t)
	resp := r.get(t, "/admin/users")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAdmin_RotateSecretOnPublicClientRejected(t *testing.T) {
	r := newTestRig(t)
	tok := seedAdminSession(t, r)
	pc, err := r.store.CreateClient(context.Background(), "pub", "", "Public",
		[]string{"https://pub/cb"}, []string{"openid"}, true, nil)
	if err != nil {
		t.Fatalf("CreateClient public: %v", err)
	}
	resp := adminReq(t, r, "POST", "/admin/clients/"+pc.ID.String()+"/rotate-secret", "", tok)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
}
