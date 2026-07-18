package api

import (
	"encoding/json"
	"hash/fnv"
	"net/http"
	"net/url"
	"slices"
	"strings"

	creds "github.com/abagile/tokyo3-base/auth/creds"
)

// handleGitHubAuthorize redirects to the standard /authorize endpoint.
// GitHub clients send: GET /login/oauth/authorize?client_id=...&redirect_uri=...&state=...&scope=...
func (s *Server) handleGitHubAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target := s.issuer + "/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {q.Get("client_id")},
		"redirect_uri":          {q.Get("redirect_uri")},
		"scope":                 {q.Get("scope")},
		"state":                 {q.Get("state")},
		"code_challenge_method": {q.Get("code_challenge_method")},
		"code_challenge":        {q.Get("code_challenge")},
	}.Encode()
	http.Redirect(w, r, target, http.StatusFound)
}

// handleGitHubAccessToken proxies to the standard token endpoint and returns
// a response in the format the GitHub client expects (JSON or form-encoded).
func (s *Server) handleGitHubAccessToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Authenticate client and exchange the code exactly like /token does.
	client, err := s.authenticateClient(r)
	if err != nil {
		githubTokenError(w, r, "bad_verification_code", err.Error())
		return
	}

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	grant, err := s.store.GetGrantByCodeHash(r.Context(), creds.HashToken(code))
	if err != nil {
		githubTokenError(w, r, "bad_verification_code", "code not found")
		return
	}
	if grant.UsedAt != nil {
		githubTokenError(w, r, "bad_verification_code", "code already used")
		return
	}
	if grant.ClientID != client.ID {
		githubTokenError(w, r, "bad_verification_code", "client mismatch")
		return
	}
	if grant.RedirectURI != redirectURI {
		githubTokenError(w, r, "bad_verification_code", "redirect_uri mismatch")
		return
	}
	if !verifyPKCE(grant.CodeChallenge, codeVerifier) {
		githubTokenError(w, r, "bad_verification_code", "PKCE verification failed")
		return
	}
	_ = s.store.MarkGrantUsed(r.Context(), grant.ID)

	user, err := s.store.GetUserByID(r.Context(), grant.UserID)
	if err != nil {
		githubTokenError(w, r, "server_error", "user not found")
		return
	}

	resp, err := s.mintTokenResponse(r, user, client, grant.Scopes, false, "")
	if err != nil {
		githubTokenError(w, r, "server_error", "token issuance failed")
		return
	}
	if err := s.logAudit(r, ActionTokenIssued, &user.ID, &client.ID, logMeta("compat", "github")); err != nil {
		s.auditFail(w, err)
		return
	}

	accessToken, _ := resp["access_token"].(string)
	scope, _ := resp["scope"].(string)

	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"token_type":   "bearer",
			"scope":        scope,
		})
		return
	}
	// Default: application/x-www-form-urlencoded (GitHub's original format)
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	vals := url.Values{
		"access_token": {accessToken},
		"token_type":   {"bearer"},
		"scope":        {scope},
	}
	_, _ = w.Write([]byte(vals.Encode()))
}

// handleGitHubUser returns user info in GitHub's API v3 JSON shape.
func (s *Server) handleGitHubUser(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}
	login, _, _ := strings.Cut(user.Email, "@")
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id":         githubID(user.ID[:]),
		"login":      login,
		"name":       user.Name,
		"email":      user.Email,
		"avatar_url": "",
		"url":        s.issuer + "/api/v3/user",
		"type":       "User",
		"site_admin": false,
	})
}

// handleGitHubUserEmails returns the authenticated user's email list.
func (s *Server) handleGitHubUserEmails(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}
	s.writeJSON(w, http.StatusOK, []map[string]any{
		{"email": user.Email, "primary": true, "verified": true, "visibility": "public"},
	})
}

// handleGitHubUserOrgs surfaces a single synthetic org derived from the issuer
// host. Teleport's github connector requires org membership for role mapping;
// we don't model orgs natively (only flat SCIMGroups), so every authenticated
// user is treated as a member of one tenant-wide org.
func (s *Server) handleGitHubUserOrgs(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	if _, err := s.store.GetUserByID(r.Context(), sess.UserID); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}
	org := s.syntheticOrgLogin()
	s.writeJSON(w, http.StatusOK, []map[string]any{githubOrgPayload(org, s.issuer)})
}

// handleGitHubUserTeams projects the user's SCIMGroup membership as GitHub
// "teams" under the synthetic org from handleGitHubUserOrgs. Always prepends
// a synthetic "members" team that every authenticated user belongs to —
// mirrors real-GitHub semantics where org members can be granted role
// mappings without an explicit team, and lets dev rigs (e.g. the Teleport
// integration) wire up teams_to_roles before any SCIM groups exist.
func (s *Server) handleGitHubUserTeams(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "list groups failed")
		return
	}
	org := s.syntheticOrgLogin()
	orgPayload := githubOrgPayload(org, s.issuer)
	teams := []map[string]any{githubTeamPayload(org, "Members", "members", orgPayload, s.issuer)}
	for _, g := range groups {
		if !slices.Contains(g.Members, sess.UserID) {
			continue
		}
		slug := githubSlug(g.DisplayName)
		if slug == "" || slug == "members" {
			continue
		}
		teams = append(teams, githubTeamPayload(org, g.DisplayName, slug, orgPayload, s.issuer))
	}
	s.writeJSON(w, http.StatusOK, teams)
}

func githubTeamPayload(org, name, slug string, orgPayload map[string]any, issuer string) map[string]any {
	return map[string]any{
		"id":           githubID([]byte(org + "/" + slug)),
		"name":         name,
		"slug":         slug,
		"description":  "",
		"privacy":      "closed",
		"permission":   "pull",
		"url":          issuer + "/api/v3/orgs/" + org + "/teams/" + slug,
		"html_url":     issuer + "/orgs/" + org + "/teams/" + slug,
		"organization": orgPayload,
	}
}

func (s *Server) syntheticOrgLogin() string {
	if u, err := url.Parse(s.issuer); err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return "auth"
}

func githubOrgPayload(login, issuer string) map[string]any {
	return map[string]any{
		"login":       login,
		"id":          githubID([]byte(login)),
		"url":         issuer + "/api/v3/orgs/" + login,
		"description": "tokyo3-auth synthetic org",
	}
}

// githubSlug normalises a SCIMGroup display name into a GitHub-style team slug
// (lowercase alphanumerics joined by single hyphens). Used for both the slug
// field and the FNV-derived numeric id, so slug stability across restarts is
// the same as display-name stability.
func githubSlug(in string) string {
	var b strings.Builder
	prevHyphen := true // suppress leading hyphen
	for _, r := range strings.ToLower(in) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			prevHyphen = false
		case !prevHyphen:
			b.WriteByte('-')
			prevHyphen = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// githubID maps a UUID byte slice to a stable positive int64 via FNV-64a.
func githubID(b []byte) int64 {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return int64(h.Sum64() & 0x7fffffffffffffff) // clear sign bit
}

func githubTokenError(w http.ResponseWriter, r *http.Request, errCode, desc string) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode, "error_description": desc})
		return
	}
	w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(url.Values{"error": {errCode}, "error_description": {desc}}.Encode()))
}
