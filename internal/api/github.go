package api

import (
	"encoding/json"
	"hash/fnv"
	"net/http"
	"net/url"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/auth"
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

	grant, err := s.store.GetGrantByCodeHash(r.Context(), auth.HashToken(code))
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
	login := strings.SplitN(user.Email, "@", 2)[0]
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
