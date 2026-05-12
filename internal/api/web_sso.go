package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/auth"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// ssoData is the template data for all SSO/authorization flow pages.
type ssoData struct {
	ClientName          string
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Email               string
	Name                string
	Error               string
	AllowRegistration   bool
	QueryString         string
}

// ssoDataFromForm builds ssoData from a form-encoded POST or GET query.
func (s *Server) ssoDataFromForm(r *http.Request, clientName, errMsg string) ssoData {
	get := func(key string) string {
		if r.Method == http.MethodPost {
			return r.FormValue(key)
		}
		return r.URL.Query().Get(key)
	}
	qv := url.Values{
		"client_id":             {get("client_id")},
		"redirect_uri":          {get("redirect_uri")},
		"response_type":         {get("response_type")},
		"scope":                 {get("scope")},
		"state":                 {get("state")},
		"nonce":                 {get("nonce")},
		"code_challenge":        {get("code_challenge")},
		"code_challenge_method": {get("code_challenge_method")},
	}
	return ssoData{
		ClientName:          clientName,
		ClientID:            get("client_id"),
		RedirectURI:         get("redirect_uri"),
		ResponseType:        get("response_type"),
		Scope:               get("scope"),
		State:               get("state"),
		Nonce:               get("nonce"),
		CodeChallenge:       get("code_challenge"),
		CodeChallengeMethod: get("code_challenge_method"),
		Email:               r.FormValue("email"),
		Error:               errMsg,
		AllowRegistration:   s.allowReg,
		QueryString:         qv.Encode(),
	}
}

// ── Registration ──────────────────────────────────────────────────────────────

func (s *Server) handleRegisterGET(w http.ResponseWriter, r *http.Request) {
	if !s.allowReg {
		http.Error(w, "registration disabled", http.StatusForbidden)
		return
	}
	s.ssoTmpl.render(w, "register.html", s.ssoDataFromForm(r, "", ""))
}

func (s *Server) handleRegisterPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allowReg {
		http.Error(w, "registration disabled", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	showErr := func(msg string) {
		d := s.ssoDataFromForm(r, "", msg)
		d.Name = r.FormValue("name")
		s.ssoTmpl.render(w, "register.html", d)
	}

	name := strings.TrimSpace(r.FormValue("name"))
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	if name == "" || email == "" || password == "" {
		showErr("All fields are required.")
		return
	}

	// PasswordComplexityRule fires when Password is set; other rules skip with nil User/Client.
	if v := s.policy.First(policy.PolicyContext{Password: password, Request: r}); v != nil {
		showErr(v.Message)
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		s.log.Error("hash password", "err", err)
		showErr("An error occurred. Please try again.")
		return
	}

	user, err := s.store.CreateUser(r.Context(), email, hash, name)
	if err != nil {
		if err == store.ErrConflict {
			showErr("An account with that email already exists.")
			return
		}
		s.log.Error("create user", "err", err)
		showErr("An error occurred. Please try again.")
		return
	}
	s.promoteIfFirstUser(r.Context(), user)
	s.logAudit(r, ActionUserCreated, &user.ID, nil, logMeta("email", email, "via", "self-registration"))
	s.provisionUser(r, provision.OpCreate, user, nil)

	// After registration, continue the OAuth2 flow by redirecting to /authorize.
	q := url.Values{
		"client_id":             {r.FormValue("client_id")},
		"redirect_uri":          {r.FormValue("redirect_uri")},
		"response_type":         {r.FormValue("response_type")},
		"scope":                 {r.FormValue("scope")},
		"state":                 {r.FormValue("state")},
		"nonce":                 {r.FormValue("nonce")},
		"code_challenge":        {r.FormValue("code_challenge")},
		"code_challenge_method": {r.FormValue("code_challenge_method")},
	}
	http.Redirect(w, r, "/authorize?"+q.Encode(), http.StatusFound)
}

// ── WebAuthn SSO MFA ──────────────────────────────────────────────────────────

// handleSSOWebAuthnPage renders the WebAuthn MFA page during the OAuth2 flow.
func (s *Server) handleSSOWebAuthnPage(w http.ResponseWriter, r *http.Request) {
	if _, err := s.getAuthStateCookie(r); err != nil {
		http.Redirect(w, r, "/authorize", http.StatusFound)
		return
	}
	s.ssoTmpl.render(w, "mfa_webauthn.html", struct{ Error string }{})
}

// handleSSOWebAuthnBegin begins WebAuthn assertion for the OAuth2 MFA step.
// User identity comes from the authState cookie, not the request body.
func (s *Server) handleSSOWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	st, err := s.getAuthStateCookie(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_request", "missing or expired auth state")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), st.UserID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_request", "user not found")
		return
	}
	optJSON, sessionID, err := s.wa.BeginLogin(r.Context(), user)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"options":    json.RawMessage(optJSON),
		"session_id": sessionID,
	})
}

// handleSSOWebAuthnFinish completes WebAuthn assertion for the OAuth2 MFA step
// and issues an authorization code redirect returned as JSON for the browser JS.
func (s *Server) handleSSOWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	st, err := s.getAuthStateCookie(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_request", "missing or expired auth state")
		return
	}
	sessionIDStr := r.URL.Query().Get("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session_id")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), st.UserID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_request", "user not found")
		return
	}
	_, err = s.wa.FinishLogin(r.Context(), user, sessionID, r)
	if err != nil {
		s.log.Error("sso webauthn finish", "err", err)
		s.writeError(w, http.StatusUnauthorized, "invalid_request", "WebAuthn verification failed")
		return
	}
	client, err := s.store.GetClientByClientID(r.Context(), st.ClientID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "client not found")
		return
	}

	clearCookie(w, authStateCookie)
	s.logAudit(r, ActionLoginMFA, &user.ID, &client.ID, logMeta("method", "webauthn"))
	s.logAudit(r, ActionLogin, &user.ID, &client.ID, nil)
	// Seat the auth_portal cookie too (post-WebAuthn-MFA branch of /authorize
	// success) so the user is also logged into auth's own portal.
	s.ensurePortalCookie(w, r, user)

	rawCode, err := auth.GenerateRawToken()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	g := &model.Grant{
		ID:            uuid.New(),
		UserID:        user.ID,
		ClientID:      client.ID,
		CodeHash:      auth.HashToken(rawCode),
		CodeChallenge: st.CodeChallenge,
		Nonce:         st.Nonce,
		Scopes:        st.Scopes,
		RedirectURI:   st.RedirectURI,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	if err := s.store.CreateGrant(r.Context(), g); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "internal error")
		return
	}
	redirect, _ := url.Parse(st.RedirectURI)
	q := redirect.Query()
	q.Set("code", rawCode)
	if st.State != "" {
		q.Set("state", st.State)
	}
	redirect.RawQuery = q.Encode()
	s.writeJSON(w, http.StatusOK, map[string]string{"redirect_to": redirect.String()})
}
