package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestGithubSlug pins the exact wire shape Teleport's github
// connector expects: lowercased alphanumerics joined by single
// hyphens, leading/trailing hyphens stripped, unicode collapsed. The
// connector matches slugs by string equality, so any drift here
// silently breaks role mapping.
func TestGithubSlug(t *testing.T) {
	cases := map[string]string{
		"Platform Engineers": "platform-engineers",
		"Data — Analytics":   "data-analytics",
		"SRE":                "sre",
		"  many   spaces  ":  "many-spaces",
		"with.dots":          "with-dots",
		"weird:chars/here":   "weird-chars-here",
		"123-numeric-start":  "123-numeric-start",
		"---all-hyphens---":  "all-hyphens",
		"":                   "",
		"嗨":                  "", // unicode-only collapses to empty
	}
	for in, want := range cases {
		if got := githubSlug(in); got != want {
			t.Errorf("githubSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestGithubID pins the deterministic + positive-int contract. GitHub
// IDs are positive int64s and Teleport's connector stores them; a
// non-deterministic ID would invalidate role-mapping caches on every
// auth restart.
func TestGithubID(t *testing.T) {
	a := githubID([]byte("platform-engineers"))
	if a < 0 {
		t.Errorf("id should be positive: %d", a)
	}
	b := githubID([]byte("platform-engineers"))
	if a != b {
		t.Errorf("id should be deterministic: %d vs %d", a, b)
	}
	c := githubID([]byte("data-analysts"))
	if a == c {
		t.Errorf("different inputs collided: %d", a)
	}
	// Sign bit cleared — output always fits in a positive int64.
	if got := githubID([]byte("\xff\xff\xff\xff\xff\xff\xff\xff")); got < 0 {
		t.Errorf("sign bit not cleared for max-byte input: %d", got)
	}
}

// TestSyntheticOrgLogin covers the issuer-hostname extraction with
// fallback to "auth" when the issuer URL is malformed or empty.
// Critical because the org login is what Teleport's
// `organization:` field has to match verbatim.
func TestSyntheticOrgLogin(t *testing.T) {
	cases := map[string]string{
		"https://id.example.com":        "id.example.com",
		"https://id.example.com:8443":   "id.example.com",
		"http://localhost":              "localhost",
		"https://auth.internal/foo/bar": "auth.internal",
		"":                              "auth", // parse succeeds but Hostname() empty
		"::not-a-url":                   "auth", // parse fails
	}
	for issuer, want := range cases {
		s := &Server{issuer: issuer}
		if got := s.syntheticOrgLogin(); got != want {
			t.Errorf("syntheticOrgLogin(%q) = %q, want %q", issuer, got, want)
		}
	}
}

// TestGithubOrgPayload exercises the JSON shape Teleport reads from
// /api/v3/user/orgs. login + id are the keys that matter; description
// + url are cosmetic but documented as present.
func TestGithubOrgPayload(t *testing.T) {
	p := githubOrgPayload("id.example.com", "https://id.example.com")
	if p["login"] != "id.example.com" {
		t.Errorf("login = %v, want id.example.com", p["login"])
	}
	if id, ok := p["id"].(int64); !ok || id <= 0 {
		t.Errorf("id should be positive int64, got %T %v", p["id"], p["id"])
	}
	if url, _ := p["url"].(string); url != "https://id.example.com/api/v3/orgs/id.example.com" {
		t.Errorf("url = %q", url)
	}
}

// TestGithubTeamPayload checks the Teleport-side contract for a
// single team entry — slug, name, organization fields, permission
// hardcoded to "pull" (Teleport doesn't currently read it but the
// shape is required).
func TestGithubTeamPayload(t *testing.T) {
	orgPayload := githubOrgPayload("id.example.com", "https://id.example.com")
	tp := githubTeamPayload("id.example.com", "Platform Engineers", "platform-engineers", orgPayload, "https://id.example.com")
	if tp["name"] != "Platform Engineers" {
		t.Errorf("name = %v", tp["name"])
	}
	if tp["slug"] != "platform-engineers" {
		t.Errorf("slug = %v", tp["slug"])
	}
	if tp["permission"] != "pull" {
		t.Errorf("permission = %v, want pull (Teleport expects this literal)", tp["permission"])
	}
	if _, ok := tp["organization"].(map[string]any); !ok {
		t.Errorf("organization is not a map: %T", tp["organization"])
	}
}

// TestGithubTokenError covers both response encodings the GitHub
// OAuth contract permits: JSON when Accept is application/json,
// form-encoded otherwise. Teleport accepts either, but content-type
// + status code MUST match the format.
func TestGithubTokenError(t *testing.T) {
	t.Run("JSON", func(t *testing.T) {
		w := newRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/login/oauth/access_token", nil)
		req.Header.Set("Accept", "application/json")
		githubTokenError(w, req, "bad_verification_code", "code already used")
		if w.code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.code)
		}
		if ct := w.headers.Get("Content-Type"); !strings.Contains(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var got map[string]string
		_ = json.Unmarshal(w.body, &got)
		if got["error"] != "bad_verification_code" || got["error_description"] != "code already used" {
			t.Errorf("body = %v", got)
		}
	})
	t.Run("FormEncoded", func(t *testing.T) {
		w := newRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/login/oauth/access_token", nil)
		githubTokenError(w, req, "bad_verification_code", "code already used")
		if w.code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", w.code)
		}
		if ct := w.headers.Get("Content-Type"); !strings.Contains(ct, "x-www-form-urlencoded") {
			t.Errorf("Content-Type = %q, want x-www-form-urlencoded", ct)
		}
		vals, err := url.ParseQuery(string(w.body))
		if err != nil {
			t.Fatalf("ParseQuery: %v", err)
		}
		if vals.Get("error") != "bad_verification_code" {
			t.Errorf("error = %q", vals.Get("error"))
		}
	})
}

// TestHandleGitHubUserOrgs / TestHandleGitHubUserTeams exercise the
// Teleport integration end-to-end through the bearerAuth middleware:
// a logged-in user issues GET /api/v3/user/orgs and receives the
// synthetic single-org list; /api/v3/user/teams projects their SCIM
// group memberships as teams under that org.
func TestHandleGitHubUserOrgs_ReturnsSyntheticOrg(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "alice@example.com", "Al1ceGithubP@ss!")
	tok := seedSessionWithToken(t, r, u.ID, false)

	resp := bearerGet(t, r, tok, "/api/v3/user/orgs")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var orgs []map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &orgs); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if len(orgs) != 1 {
		t.Fatalf("orgs length = %d, want 1 (synthetic)", len(orgs))
	}
	// Issuer is "https://issuer.test" in the rig; hostname is the login.
	if orgs[0]["login"] != "issuer.test" {
		t.Errorf("orgs[0].login = %v, want issuer.test", orgs[0]["login"])
	}
}

func TestHandleGitHubUserTeams_ProjectsSCIMGroups(t *testing.T) {
	r := newTestRig(t)
	ctx := context.Background()
	u := seedTestUser(t, r.store, "bob@example.com", "B0bGithubP@ss12!")
	tok := seedSessionWithToken(t, r, u.ID, false)

	// Two SCIM groups, user is in both. Plus an unrelated group the
	// user is NOT in — must not appear in the teams list.
	g1, _ := r.store.CreateGroup(ctx, "Platform Engineers")
	g2, _ := r.store.CreateGroup(ctx, "SRE")
	other, _ := r.store.CreateGroup(ctx, "Other Team")
	_ = r.store.AddGroupMember(ctx, g1.ID, u.ID)
	_ = r.store.AddGroupMember(ctx, g2.ID, u.ID)
	_ = other // unused, intentional

	resp := bearerGet(t, r, tok, "/api/v3/user/teams")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var teams []map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &teams); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}

	// Expect: "members" (synthetic always-present) + "platform-engineers" + "sre"
	// = 3 entries. The user's two groups + the synthetic; the Other
	// Team they're NOT in stays out.
	slugs := map[string]bool{}
	for _, tm := range teams {
		slugs[tm["slug"].(string)] = true
	}
	for _, want := range []string{"members", "platform-engineers", "sre"} {
		if !slugs[want] {
			t.Errorf("missing team slug %q in %v", want, slugs)
		}
	}
	if slugs["other-team"] {
		t.Error("non-member group leaked into teams list")
	}
}

// TestHandleGitHubUser_BasicShape verifies the GitHub-compat user
// shape Teleport reads. The connector uses `login` as the principal
// identifier and `id` for stable joins, so both must round-trip
// correctly.
func TestHandleGitHubUser_BasicShape(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "carol@example.com", "C@rolGithubP@ss1!")
	tok := seedSessionWithToken(t, r, u.ID, false)

	resp := bearerGet(t, r, tok, "/api/v3/user")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var got map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if got["login"] != "carol" {
		t.Errorf("login = %v, want carol (email local-part)", got["login"])
	}
	if got["email"] != "carol@example.com" {
		t.Errorf("email = %v", got["email"])
	}
	if got["type"] != "User" {
		t.Errorf("type = %v, want User", got["type"])
	}
	if _, ok := got["id"].(float64); !ok {
		t.Errorf("id should be a number, got %T", got["id"])
	}
}

// TestHandleGitHubUserEmails_SingleVerifiedEntry covers the
// /api/v3/user/emails endpoint. GitHub's API allows multiple emails
// per user with primary/verified flags; auth maps the single account
// email to "primary + verified + public" since there's no concept of
// secondary emails in the data model.
func TestHandleGitHubUserEmails_SingleVerifiedEntry(t *testing.T) {
	r := newTestRig(t)
	u := seedTestUser(t, r.store, "dave@example.com", "D@veGithubP@ss12!")
	tok := seedSessionWithToken(t, r, u.ID, false)

	resp := bearerGet(t, r, tok, "/api/v3/user/emails")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var emails []map[string]any
	body, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(body, &emails); err != nil {
		t.Fatalf("decode: %v body=%s", err, body)
	}
	if len(emails) != 1 {
		t.Fatalf("emails length = %d, want 1", len(emails))
	}
	if emails[0]["email"] != "dave@example.com" {
		t.Errorf("email = %v", emails[0]["email"])
	}
	if emails[0]["primary"] != true || emails[0]["verified"] != true {
		t.Errorf("primary/verified flags wrong: %v", emails[0])
	}
}

// ── small response recorder ──────────────────────────────────────────

// recorder is a tiny http.ResponseWriter for unit-testing helpers
// that don't fit the full httptest server pattern. Records status,
// headers, body for assertion.
type recorder struct {
	code    int
	headers http.Header
	body    []byte
}

func newRecorder() *recorder { return &recorder{code: http.StatusOK, headers: http.Header{}} }

func (r *recorder) Header() http.Header { return r.headers }
func (r *recorder) WriteHeader(s int)   { r.code = s }
func (r *recorder) Write(b []byte) (int, error) {
	r.body = append(r.body, b...)
	return len(b), nil
}

// bearerGet issues a GET with the rig's no-follow client and an
// Authorization: Bearer <tok> header. Mirrors the pattern used by
// the credential_process tests but doesn't push a body.
func bearerGet(t *testing.T, r *testRig, tok, path string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, r.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	c := &http.Client{CheckRedirect: noFollow}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}
