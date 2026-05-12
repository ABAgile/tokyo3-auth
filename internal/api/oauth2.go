package api

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/auth"
	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
)

// authState is held in an AES-GCM-encrypted cookie during the interactive auth flow.
type authState struct {
	UserID        uuid.UUID `json:"uid"`
	AuthTime      time.Time `json:"at"`
	MFAVerified   bool      `json:"mfa"`
	MFAAMR        []string  `json:"amr,omitempty"`
	ClientID      string    `json:"cid"`
	RedirectURI   string    `json:"ruri"`
	Scopes        []string  `json:"sc"`
	State         string    `json:"st"`
	Nonce         string    `json:"nc"`
	CodeChallenge string    `json:"cc"`
	Exp           time.Time `json:"exp"`
}

const authStateCookie = "auth_state"
const authStateTTL = 15 * time.Minute

// Token / session TTLs. Three layers, all enforced together:
//
//	accessTokenTTL     — bearer access token life. Matches the response's
//	                     `expires_in`. Slid forward by portal hits and by
//	                     each successful refresh-token exchange.
//	refreshTokenTTL    — refresh-token life. Slid forward only by the
//	                     /token refresh_token grant, never by portal hits
//	                     (the portal doesn't see the refresh credential).
//	absoluteSessionTTL — hard ceiling from CreatedAt. Even sliding can't
//	                     push expiry past this point — the user must
//	                     re-authenticate at /authorize to mint a new row.
//
// PCI 8.2.8 idle target = accessTokenTTL. Refresh token rotation handled by
// handleTokenRefresh (a new refresh credential is issued on each use, the
// old one stays valid until rotation lands).
const (
	accessTokenTTL     = 15 * time.Minute
	refreshTokenTTL    = 1 * time.Hour
	absoluteSessionTTL = 4 * time.Hour
)

// capByAbsolute returns min(deadline, createdAt + absoluteSessionTTL) — used
// when sliding a session's expiry to ensure no slide pushes past the hard
// ceiling tied to session creation.
func capByAbsolute(deadline, createdAt time.Time) time.Time {
	hardCap := createdAt.Add(absoluteSessionTTL)
	if deadline.After(hardCap) {
		return hardCap
	}
	return deadline
}

// ── authorize endpoint ────────────────────────────────────────────────────────

func (s *Server) handleAuthorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.store.GetClientByClientID(r.Context(), q.Get("client_id"))
	if err != nil {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !validRedirectURI(client, redirectURI) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	// OIDC §3.1.2.1 — prompt: "login" forces re-auth, "none" forbids any UI.
	// Anything else (or absent) means: silently re-use an existing session if
	// one is valid, otherwise fall through to the login form.
	prompt := q.Get("prompt")
	if prompt != "login" {
		if ok := s.trySilentSSO(w, r, client, q); ok {
			return
		}
		if prompt == "none" {
			// User has no usable session and we can't show a login form.
			redirectWithOIDCError(w, r, redirectURI, "login_required", q.Get("state"))
			return
		}
	}
	d := s.ssoDataFromForm(r, client.Name, "")
	s.ssoTmpl.render(w, "login.html", d)
}

// trySilentSSO attempts to short-circuit the OIDC authorize step when the
// browser already presents a valid auth_portal cookie. Returns true iff a
// fresh authorization code was issued (and the response was written).
//
// Criteria — all must hold:
//   - auth_portal cookie present + decryptable
//   - session row exists, not expired
//   - user is active
//   - if user.MFAEnabled, session.MFAVerified == true
//   - login_hint (when present) matches the session user's email
//   - max_age (when present) hasn't elapsed since session.CreatedAt
//   - policy engine raises no violation (e.g. account lockout)
func (s *Server) trySilentSSO(w http.ResponseWriter, r *http.Request, client *model.Client, q url.Values) bool {
	sess, user, rawToken, err := s.readAuthPortalSession(r)
	if err != nil || sess == nil {
		return false
	}
	if !user.Active {
		return false
	}
	if user.MFAEnabled && !sess.MFAVerified {
		return false
	}
	if hint := q.Get("login_hint"); hint != "" && !strings.EqualFold(strings.TrimSpace(hint), user.Email) {
		return false
	}
	if mas := q.Get("max_age"); mas != "" {
		if maxAge, parseErr := time.ParseDuration(mas + "s"); parseErr == nil && maxAge > 0 {
			if time.Since(sess.CreatedAt) > maxAge {
				return false
			}
		}
	}
	pctx := policy.PolicyContext{User: user, Client: client, MFAVerified: sess.MFAVerified, Request: r}
	if v := s.policy.First(pctx); v != nil {
		return false
	}

	// Fresh activity + slide cookie + audit, then issue the code.
	s.slidePortalSession(w, r, sess, rawToken)
	if err := s.logAudit(r, ActionLogin, &user.ID, &client.ID, logMeta("via", "silent_sso")); err != nil {
		s.auditFail(w, err)
		return true
	}
	scopes := splitScopes(q.Get("scope"))
	s.issueCodeAndRedirect(w, r, user, client, scopes, q.Get("state"), q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri"))
	return true
}

// redirectWithOIDCError redirects the browser back to the RP's redirect_uri
// with an OIDC-formatted error (RFC 6749 §4.1.2.1). Used for `prompt=none`
// when no valid session exists — the spec requires the error to be returned
// to the RP, not displayed inline.
func redirectWithOIDCError(w http.ResponseWriter, r *http.Request, redirectURI, code, state string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	qq := u.Query()
	qq.Set("error", code)
	if state != "" {
		qq.Set("state", state)
	}
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	nonce := r.FormValue("nonce")
	codeChallenge := r.FormValue("code_challenge")
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	client, err := s.store.GetClientByClientID(r.Context(), clientID)
	if err != nil || !validRedirectURI(client, redirectURI) {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}

	showLoginErr := func(msg string) {
		d := s.ssoDataFromForm(r, client.Name, msg)
		d.Email = email
		s.ssoTmpl.render(w, "login.html", d)
	}

	user, err := s.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !auth.CheckPassword(user.PasswordHash, password)) {
		if user != nil {
			s.incrementFailedAttempts(r, user)
		}
		if err := s.logAudit(r, ActionLoginFailed, nil, &client.ID, logMeta("email", email)); err != nil {
			s.auditFail(w, err)
			return
		}
		showLoginErr("Invalid email or password.")
		return
	}
	if err != nil {
		s.log.Error("get user", "err", err)
		showLoginErr("An error occurred. Please try again.")
		return
	}
	if !user.Active {
		showLoginErr("Account is disabled.")
		return
	}

	pctx := policy.PolicyContext{User: user, Client: client, Password: password, Request: r}
	if v := s.policy.First(pctx); v != nil {
		showLoginErr(v.Message)
		return
	}
	_ = s.store.UpdateUserFailedAttempts(r.Context(), user.ID, 0, nil)

	scopes := splitScopes(scope)
	authTime := time.Now().UTC()

	if user.MFAEnabled {
		st := &authState{
			UserID: user.ID, AuthTime: authTime,
			ClientID: clientID, RedirectURI: redirectURI,
			Scopes: scopes, State: state, Nonce: nonce,
			CodeChallenge: codeChallenge, Exp: time.Now().Add(authStateTTL),
		}
		if err := s.setAuthStateCookie(w, st); err != nil {
			showLoginErr("An error occurred. Please try again.")
			return
		}
		// Prefer TOTP if enrolled; otherwise fall back to WebAuthn.
		totpCred, totpErr := s.store.GetTOTPByUserID(r.Context(), user.ID)
		if totpErr == nil && totpCred.Enabled {
			s.ssoTmpl.render(w, "mfa_totp.html", struct{ AuthState, Error string }{})
		} else {
			http.Redirect(w, r, "/authorize/mfa/webauthn", http.StatusFound)
		}
		return
	}

	if err := s.logAudit(r, ActionLogin, &user.ID, &client.ID, nil); err != nil {
		s.auditFail(w, err)
		return
	}
	s.issueCodeAndRedirect(w, r, user, client, scopes, state, nonce, codeChallenge, redirectURI)
}

// handleMFATOTPPost handles POST /authorize/mfa/totp.
func (s *Server) handleMFATOTPPost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	st, err := s.getAuthStateCookie(r)
	if err != nil {
		http.Redirect(w, r, "/authorize", http.StatusFound)
		return
	}

	user, err := s.store.GetUserByID(r.Context(), st.UserID)
	if err != nil {
		http.Error(w, "user not found", http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	if err := mfa.VerifyTOTP(r.Context(), s.store, s.kp, user.ID, code); err != nil {
		if err := s.logAudit(r, ActionLoginMFAFailed, &user.ID, nil, nil); err != nil {
			s.auditFail(w, err)
			return
		}
		s.ssoTmpl.render(w, "mfa_totp.html", struct{ AuthState, Error string }{Error: "Invalid code. Please try again."})
		return
	}

	client, err := s.store.GetClientByClientID(r.Context(), st.ClientID)
	if err != nil {
		http.Error(w, "invalid client", http.StatusBadRequest)
		return
	}

	clearCookie(w, authStateCookie)
	if err := s.logAudit(r, ActionLoginMFA, &user.ID, &client.ID, nil); err != nil {
		s.auditFail(w, err)
		return
	}
	if err := s.logAudit(r, ActionLogin, &user.ID, &client.ID, nil); err != nil {
		s.auditFail(w, err)
		return
	}
	s.issueCodeAndRedirect(w, r, user, client, st.Scopes, st.State, st.Nonce, st.CodeChallenge, st.RedirectURI)
}

func (s *Server) issueCodeAndRedirect(w http.ResponseWriter, r *http.Request,
	user *model.User, client *model.Client,
	scopes []string, state, nonce, codeChallenge, redirectURI string,
) {
	rawCode, err := auth.GenerateRawToken()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	g := &model.Grant{
		ID:            uuid.New(),
		UserID:        user.ID,
		ClientID:      client.ID,
		CodeHash:      auth.HashToken(rawCode),
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
		Scopes:        scopes,
		RedirectURI:   redirectURI,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	if err := s.store.CreateGrant(r.Context(), g); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	redirect, _ := url.Parse(redirectURI)
	q := redirect.Query()
	q.Set("code", rawCode)
	if state != "" {
		q.Set("state", state)
	}
	redirect.RawQuery = q.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// ── token endpoint ────────────────────────────────────────────────────────────

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "bad form")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.handleTokenAuthCode(w, r)
	case "refresh_token":
		s.handleTokenRefresh(w, r)
	case "client_credentials":
		s.handleTokenClientCreds(w, r)
	default:
		s.writeError(w, http.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type")
	}
}

func (s *Server) handleTokenAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	redirectURI := r.FormValue("redirect_uri")

	client, err := s.authenticateClient(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	grant, err := s.store.GetGrantByCodeHash(r.Context(), auth.HashToken(code))
	if errors.Is(err, store.ErrNotFound) || (err == nil && grant.UsedAt != nil) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "code not found or already used")
		return
	}
	if err != nil {
		s.log.Error("get grant", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	if grant.ClientID != client.ID {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	if grant.RedirectURI != redirectURI {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	if time.Now().After(grant.ExpiresAt) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}
	if !verifyPKCE(grant.CodeChallenge, codeVerifier) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	_ = s.store.MarkGrantUsed(r.Context(), grant.ID)

	user, err := s.store.GetUserByID(r.Context(), grant.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}

	resp, err := s.mintTokenResponse(r, user, client, grant.Scopes, true, grant.Nonce)
	if err != nil {
		s.log.Error("mint tokens", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	if err := s.logAudit(r, ActionTokenIssued, &user.ID, &client.ID, logMeta("scopes", grant.Scopes)); err != nil {
		s.auditFail(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	rawRefresh := r.FormValue("refresh_token")
	client, err := s.authenticateClient(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	sess, err := s.store.GetSessionByRefreshTokenHash(r.Context(), auth.HashToken(rawRefresh))
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token not found")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	if sess.ClientID != client.ID {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "client mismatch")
		return
	}
	now := time.Now()
	if now.After(sess.RefreshExpiresAt) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	// Absolute session cap: no amount of refreshing extends the session past
	// CreatedAt + absoluteSessionTTL. Beyond that the user must re-authenticate
	// at /authorize, which mints a fresh row.
	if now.After(sess.CreatedAt.Add(absoluteSessionTTL)) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "session age cap exceeded; re-authenticate")
		return
	}

	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}

	newAccess, err := auth.GenerateRawToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "token generation failed")
		return
	}
	newRefresh, err := auth.GenerateRawToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "token generation failed")
		return
	}
	newAccessExp := capByAbsolute(now.Add(accessTokenTTL), sess.CreatedAt)
	newRefreshExp := capByAbsolute(now.Add(refreshTokenTTL), sess.CreatedAt)
	if err := s.store.RotateRefreshToken(r.Context(), sess.ID, auth.HashToken(newRefresh), newAccessExp, newRefreshExp); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	idToken := ""
	if containsStr(sess.Scopes, "openid") {
		// aud must be the OAuth client_id string the RP is configured with,
		// not the database row UUID — RPs (e.g. go-oidc) reject otherwise.
		idToken, err = s.signer.MintIDToken(
			sess.UserID.String(), client.ClientID,
			user.Email, user.Name, "", sess.Scopes, sess.MFAVerified, nil, time.Now(), sess.ID.String(),
		)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "server_error", "id token failed")
			return
		}
	}

	resp := map[string]any{
		"access_token":  newAccess,
		"token_type":    "Bearer",
		"expires_in":    int(time.Until(newAccessExp).Seconds()),
		"refresh_token": newRefresh,
		"scope":         strings.Join(sess.Scopes, " "),
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	if err := s.logAudit(r, ActionTokenRefreshed, &sess.UserID, &sess.ClientID, nil); err != nil {
		s.auditFail(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTokenClientCreds(w http.ResponseWriter, r *http.Request) {
	client, err := s.authenticateClient(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	if client.Public {
		s.writeError(w, http.StatusUnauthorized, "invalid_client", "public clients cannot use client_credentials")
		return
	}

	rawAccess, err := auth.GenerateRawToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "token generation failed")
		return
	}
	rawRefresh, _ := auth.GenerateRawToken() // internal placeholder, not exposed
	scopes := splitScopes(r.FormValue("scope"))
	now := time.Now()
	sess := &model.Session{
		ID: uuid.New(), ClientID: client.ID,
		AccessTokenHash:  auth.HashToken(rawAccess),
		RefreshTokenHash: auth.HashToken(rawRefresh),
		Scopes:           scopes,
		AccessExpiresAt:  now.Add(accessTokenTTL),
		RefreshExpiresAt: now.Add(refreshTokenTTL),
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	if err := s.logAudit(r, ActionTokenIssued, nil, &client.ID, logMeta("grant_type", "client_credentials")); err != nil {
		s.auditFail(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"access_token": rawAccess,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"scope":        strings.Join(scopes, " "),
	})
}

// ── userinfo ──────────────────────────────────────────────────────────────────

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}
	claims := map[string]any{
		"sub":                sess.UserID.String(),
		"email":              user.Email,
		"preferred_username": user.Email,
	}
	if containsStr(sess.Scopes, "profile") {
		claims["name"] = user.Name
	}
	s.writeJSON(w, http.StatusOK, claims)
}

// ── revoke ────────────────────────────────────────────────────────────────────

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	token := r.FormValue("token")
	if token != "" {
		hash := auth.HashToken(token)
		if sess, err := s.store.GetSessionByAccessTokenHash(r.Context(), hash); err == nil {
			if err := s.logAudit(r, ActionTokenRevoked, &sess.UserID, &sess.ClientID, nil); err != nil {
				s.auditFail(w, err)
				return
			}
			_ = s.store.DeleteSession(r.Context(), sess.ID)
		} else if sess, err := s.store.GetSessionByRefreshTokenHash(r.Context(), hash); err == nil {
			if err := s.logAudit(r, ActionTokenRevoked, &sess.UserID, &sess.ClientID, nil); err != nil {
				s.auditFail(w, err)
				return
			}
			_ = s.store.DeleteSession(r.Context(), sess.ID)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func (s *Server) mintTokenResponse(r *http.Request, user *model.User, client *model.Client, scopes []string, mfaVerified bool, nonce string) (map[string]any, error) {
	rawAccess, err := auth.GenerateRawToken()
	if err != nil {
		return nil, err
	}
	rawRefresh, err := auth.GenerateRawToken()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	sess := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		ClientID:         client.ID,
		AccessTokenHash:  auth.HashToken(rawAccess),
		RefreshTokenHash: auth.HashToken(rawRefresh),
		Scopes:           scopes,
		AccessExpiresAt:  now.Add(accessTokenTTL),
		RefreshExpiresAt: now.Add(refreshTokenTTL),
		MFAVerified:      mfaVerified,
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	resp := map[string]any{
		"access_token":  rawAccess,
		"token_type":    "Bearer",
		"expires_in":    int(accessTokenTTL.Seconds()),
		"refresh_token": rawRefresh,
		"scope":         strings.Join(scopes, " "),
	}
	if containsStr(scopes, "openid") {
		idToken, err := s.signer.MintIDToken(
			user.ID.String(), client.ClientID,
			user.Email, user.Name, nonce, scopes, mfaVerified, nil, time.Now(), sess.ID.String(),
		)
		if err != nil {
			return nil, fmt.Errorf("mint id token: %w", err)
		}
		resp["id_token"] = idToken
	}
	return resp, nil
}

func (s *Server) authenticateClient(r *http.Request) (*model.Client, error) {
	clientID, clientSecret := r.FormValue("client_id"), r.FormValue("client_secret")
	if u, p, ok := r.BasicAuth(); ok && clientID == "" {
		clientID, clientSecret = u, p
	}
	client, err := s.store.GetClientByClientID(r.Context(), clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("unknown client")
	}
	if err != nil {
		return nil, fmt.Errorf("internal error")
	}
	if !client.Public {
		if clientSecret == "" {
			return nil, fmt.Errorf("client_secret required")
		}
		if auth.HashToken(clientSecret) != client.ClientSecretHash {
			return nil, fmt.Errorf("invalid client_secret")
		}
	}
	return client, nil
}

func (s *Server) incrementFailedAttempts(r *http.Request, user *model.User) {
	count := user.FailedAttempts + 1
	var lockedUntil *time.Time
	if count >= 10 {
		t := time.Now().Add(30 * time.Minute)
		lockedUntil = &t
	}
	_ = s.store.UpdateUserFailedAttempts(r.Context(), user.ID, count, lockedUntil)
}

func validRedirectURI(client *model.Client, uri string) bool {
	return slices.Contains(client.RedirectURIs, uri)
}

func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" {
		return true
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func splitScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// ── auth state cookie (AES-GCM encrypted, short-lived) ───────────────────────

func (s *Server) setAuthStateCookie(w http.ResponseWriter, st *authState) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	enc, err := bcrypto.Seal(s.masterKey, data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: authStateCookie, Value: base64.RawURLEncoding.EncodeToString(enc),
		Path: "/", MaxAge: int(authStateTTL.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) getAuthStateCookie(r *http.Request) (*authState, error) {
	c, err := r.Cookie(authStateCookie)
	if err != nil {
		return nil, err
	}
	enc, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	plain, err := bcrypto.Open(s.masterKey, enc)
	if err != nil {
		return nil, fmt.Errorf("decrypt auth state: %w", err)
	}
	var st authState
	if err := json.Unmarshal(plain, &st); err != nil {
		return nil, err
	}
	if time.Now().After(st.Exp) {
		return nil, fmt.Errorf("auth state expired")
	}
	return &st, nil
}

func clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", MaxAge: -1, Path: "/"})
}
