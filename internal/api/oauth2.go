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

// ── authorize endpoint ────────────────────────────────────────────────────────

func (s *Server) handleAuthorizeGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.store.GetClientByClientID(r.Context(), q.Get("client_id"))
	if err != nil {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if !validRedirectURI(client, q.Get("redirect_uri")) {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	d := s.ssoDataFromForm(r, client.Name, "")
	s.ssoTmpl.render(w, "login.html", d)
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
	if time.Now().After(sess.ExpiresAt) {
		s.writeError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
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
	expiry := time.Now().Add(24 * time.Hour)
	if err := s.store.RotateRefreshToken(r.Context(), sess.ID, auth.HashToken(newRefresh), expiry); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}

	idToken := ""
	if containsStr(sess.Scopes, "openid") {
		// aud must be the OAuth client_id string the RP is configured with,
		// not the database row UUID — RPs (e.g. go-oidc) reject otherwise.
		idToken, err = s.signer.MintIDToken(
			sess.UserID.String(), client.ClientID,
			user.Email, user.Name, "", sess.Scopes, sess.MFAVerified, nil, time.Now(),
		)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "server_error", "id token failed")
			return
		}
	}

	resp := map[string]any{
		"access_token":  newAccess,
		"token_type":    "Bearer",
		"expires_in":    3600,
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
	sess := &model.Session{
		ID: uuid.New(), ClientID: client.ID,
		AccessTokenHash:  auth.HashToken(rawAccess),
		RefreshTokenHash: auth.HashToken(rawRefresh),
		Scopes:           scopes, ExpiresAt: time.Now().Add(time.Hour),
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
		"expires_in":   3600,
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
	sess := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		ClientID:         client.ID,
		AccessTokenHash:  auth.HashToken(rawAccess),
		RefreshTokenHash: auth.HashToken(rawRefresh),
		Scopes:           scopes,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		MFAVerified:      mfaVerified,
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	resp := map[string]any{
		"access_token":  rawAccess,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": rawRefresh,
		"scope":         strings.Join(scopes, " "),
	}
	if containsStr(scopes, "openid") {
		idToken, err := s.signer.MintIDToken(
			user.ID.String(), client.ClientID,
			user.Email, user.Name, nonce, scopes, mfaVerified, nil, time.Now(),
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
