package api

import (
	"context"
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
	iMFA "github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/provision/awsfed"
	"github.com/abagile/tokyo3-auth/internal/store"
	bcrypto "github.com/abagile/tokyo3-base/crypto"
	"github.com/google/uuid"
)

// portalClientUUID is the sentinel client used for portal sessions.
// Seeded by migration 005_portal_client.sql.
var portalClientUUID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// promoteIfFirstUser flips u to admin when they are the only row in the users
// table — bootstraps the very first admin from a self-registration without
// requiring CLI access. No-op on every subsequent registration. Mutates u in
// place so the caller's downstream provisioning sees the admin flag.
func (s *Server) promoteIfFirstUser(ctx context.Context, u *model.User) {
	if u == nil {
		return
	}
	n, err := s.store.CountUsers(ctx)
	if err != nil {
		s.log.Warn("bootstrap admin: count users", "err", err)
		return
	}
	if n != 1 {
		return
	}
	if err := s.store.SetUserAdmin(ctx, u.ID, true); err != nil {
		s.log.Warn("bootstrap admin: set admin", "err", err)
		return
	}
	u.IsAdmin = true
	s.log.Info("bootstrap admin: promoted first registered user", "user_id", u.ID, "email", u.Email)
}

const portalCookie = "auth_portal"
const portalLoginCookie = "portal_login"
const portalCookieTTL = 15 * time.Minute // sliding idle timeout — extended on every authenticated portal hit
const portalLoginCookieTTL = 10 * time.Minute
const portalTOTPCookie = "portal_totp"

type portalCtxKey struct{}

type portalCtx struct {
	Session *model.Session
	User    *model.User
}

func portalFromCtx(r *http.Request) *portalCtx {
	p, _ := r.Context().Value(portalCtxKey{}).(*portalCtx)
	return p
}

// portalBase is embedded in all portal page data structs.
type portalBase struct {
	ActivePage string
	UserEmail  string
	IsAdmin    bool
	User       *model.User
}

func newPortalBase(pc *portalCtx, page string) portalBase {
	return portalBase{
		ActivePage: page,
		UserEmail:  pc.User.Email,
		IsAdmin:    pc.User.IsAdmin,
		User:       pc.User,
	}
}

// ── Auth middleware ───────────────────────────────────────────────────────────

func (s *Server) portalAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, user, rawToken, err := s.readAuthPortalSession(r)
		if err != nil || sess == nil {
			clearCookie(w, portalCookie)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		s.slidePortalSession(w, r, sess, rawToken)
		pc := &portalCtx{Session: sess, User: user}
		ctx := context.WithValue(r.Context(), portalCtxKey{}, pc)
		next(w, r.WithContext(ctx))
	}
}

// readAuthPortalSession unwraps the auth_portal cookie, looks up the session,
// validates expiry, and loads the user. Returns (nil, nil, "", nil) when no
// cookie is present so callers can distinguish "anonymous browser" from
// "tampered cookie / expired session" — the former is normal on /authorize,
// the latter should clear the cookie and force re-auth. The raw bearer token
// is returned so callers (the portalAuth middleware, silent SSO) can re-seal
// it into a fresh cookie when sliding the session.
func (s *Server) readAuthPortalSession(r *http.Request) (*model.Session, *model.User, string, error) {
	c, err := r.Cookie(portalCookie)
	if err != nil {
		return nil, nil, "", nil
	}
	enc, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, nil, "", err
	}
	raw, err := bcrypto.Open(s.masterKey, enc)
	if err != nil {
		return nil, nil, "", err
	}
	rawToken := string(raw)
	sess, err := s.store.GetSessionByAccessTokenHash(r.Context(), auth.HashToken(rawToken))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, "", err
	}
	if err != nil {
		s.log.Error("portal session lookup", "err", err)
		return nil, nil, "", err
	}
	now := time.Now()
	if now.After(sess.AccessExpiresAt) {
		return nil, nil, "", fmt.Errorf("access token expired")
	}
	if now.After(sess.CreatedAt.Add(absoluteSessionTTL)) {
		return nil, nil, "", fmt.Errorf("session age cap exceeded")
	}
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		return nil, nil, "", err
	}
	return sess, user, rawToken, nil
}

// slidePortalSession bumps the session's access_expires_at to
// now+portalCookieTTL (capped at CreatedAt+absoluteSessionTTL), records
// activity, and re-issues the auth_portal cookie so the browser's MaxAge
// resets too. Best-effort: failures are logged but don't block the request —
// the existing cookie still works until the DB row expires. The cookie
// MaxAge is also capped at the remaining absolute lifetime so the browser
// drops the cookie around the same time the server stops honouring it.
func (s *Server) slidePortalSession(w http.ResponseWriter, r *http.Request, sess *model.Session, rawToken string) {
	now := time.Now().UTC()
	newExpiry := capByAbsolute(now.Add(portalCookieTTL), sess.CreatedAt)
	if err := s.store.ExtendSessionExpiry(r.Context(), sess.ID, newExpiry); err != nil {
		s.log.Warn("extend session expiry", "err", err)
	} else {
		sess.AccessExpiresAt = newExpiry
	}
	_ = s.store.UpdateSessionActivity(r.Context(), sess.ID, now)
	cookieMaxAge := time.Until(newExpiry)
	if cookieMaxAge <= 0 {
		cookieMaxAge = time.Second // ensure cookie is set with a positive MaxAge; absolute cap will reject the next hit
	}
	if err := s.setPortalCookie(w, rawToken, cookieMaxAge, portalCookie); err != nil {
		s.log.Warn("re-set portal cookie", "err", err)
	}
}

func (s *Server) portalAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return s.portalAuth(func(w http.ResponseWriter, r *http.Request) {
		pc := portalFromCtx(r)
		if !pc.User.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// ── Cookie helpers ────────────────────────────────────────────────────────────

func (s *Server) setPortalCookie(w http.ResponseWriter, rawToken string, ttl time.Duration, name string) error {
	enc, err := bcrypto.Seal(s.masterKey, []byte(rawToken))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    base64.RawURLEncoding.EncodeToString(enc),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// portalLoginState is stored encrypted in portalLoginCookie during the MFA step.
type portalLoginState struct {
	UserID uuid.UUID `json:"uid"`
	Exp    time.Time `json:"exp"`
}

func (s *Server) setPortalLoginCookie(w http.ResponseWriter, userID uuid.UUID) error {
	data, _ := json.Marshal(portalLoginState{UserID: userID, Exp: time.Now().Add(portalLoginCookieTTL)})
	enc, err := bcrypto.Seal(s.masterKey, data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: portalLoginCookie, Value: base64.RawURLEncoding.EncodeToString(enc),
		Path: "/", MaxAge: int(portalLoginCookieTTL.Seconds()), HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) getPortalLoginCookie(r *http.Request) (*portalLoginState, error) {
	c, err := r.Cookie(portalLoginCookie)
	if err != nil {
		return nil, err
	}
	enc, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil, err
	}
	raw, err := bcrypto.Open(s.masterKey, enc)
	if err != nil {
		return nil, err
	}
	var st portalLoginState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	if time.Now().After(st.Exp) {
		return nil, errors.New("expired")
	}
	return &st, nil
}

// totpPending is stored encrypted in portalTOTPCookie during TOTP enrollment.
type totpPending struct {
	OTPURI string    `json:"uri"`
	Secret string    `json:"secret"`
	Exp    time.Time `json:"exp"`
}

func (s *Server) setTOTPPendingCookie(w http.ResponseWriter, uri, secret string) error {
	data, _ := json.Marshal(totpPending{OTPURI: uri, Secret: secret, Exp: time.Now().Add(10 * time.Minute)})
	enc, err := bcrypto.Seal(s.masterKey, data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name: portalTOTPCookie, Value: base64.RawURLEncoding.EncodeToString(enc),
		Path: "/portal", MaxAge: 600, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func (s *Server) getTOTPPendingCookie(r *http.Request) *totpPending {
	c, err := r.Cookie(portalTOTPCookie)
	if err != nil {
		return nil
	}
	enc, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	raw, err := bcrypto.Open(s.masterKey, enc)
	if err != nil {
		return nil
	}
	var tp totpPending
	if err := json.Unmarshal(raw, &tp); err != nil {
		return nil
	}
	if time.Now().After(tp.Exp) {
		return nil
	}
	return &tp
}

// ── Portal login ──────────────────────────────────────────────────────────────

func (s *Server) handlePortalLoginGET(w http.ResponseWriter, r *http.Request) {
	// Already-signed-in users hitting /portal/login are bounced to the
	// dashboard, matching the dominant industry pattern (Google, GitHub,
	// Slack). Escape hatch: ?prompt=login forces the form so a user can
	// authenticate as a different identity in the same browser — the
	// credential-check path then runs ensurePortalCookie's user-switch
	// cleanup against the prior session.
	if r.URL.Query().Get("prompt") != "login" {
		if sess, _, _, err := s.readAuthPortalSession(r); err == nil && sess != nil {
			http.Redirect(w, r, "/portal", http.StatusFound)
			return
		}
	}
	s.ssoTmpl.render(w, "portal_login.html", struct {
		Error, Email  string
		AllowRegister bool
	}{Error: r.URL.Query().Get("error"), AllowRegister: s.allowReg})
}

// ── Portal registration ───────────────────────────────────────────────────────

func (s *Server) handlePortalRegisterGET(w http.ResponseWriter, r *http.Request) {
	if !s.allowReg {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	// Already-signed-in users hitting /portal/register are bounced to the
	// dashboard — register doesn't make sense for an authenticated user.
	// No prompt=login escape hatch here: re-registering is a meaningless
	// action; switch users via /portal/login?prompt=login if intended.
	if sess, _, _, err := s.readAuthPortalSession(r); err == nil && sess != nil {
		http.Redirect(w, r, "/portal", http.StatusFound)
		return
	}
	s.ssoTmpl.render(w, "portal_register.html", struct {
		Error, Email, Name string
	}{})
}

func (s *Server) handlePortalRegisterPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allowReg {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")
	confirm := r.FormValue("confirm")

	showErr := func(msg string) {
		s.ssoTmpl.render(w, "portal_register.html", struct {
			Error, Email, Name string
		}{msg, email, name})
	}

	if password != confirm {
		showErr("Passwords do not match.")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		showErr("An error occurred. Please try again.")
		return
	}
	if name == "" {
		name = strings.SplitN(email, "@", 2)[0]
	}

	pctx := policy.PolicyContext{Password: password, Request: r}
	if v := s.policy.First(pctx); v != nil {
		showErr(v.Message)
		return
	}

	user, err := s.store.CreateUser(r.Context(), email, hash, name)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			showErr("An account with that email already exists.")
			return
		}
		s.log.Error("portal register create user", "err", err)
		showErr("An error occurred. Please try again.")
		return
	}

	s.promoteIfFirstUser(r.Context(), user)
	if err := s.logAudit(r, ActionUserCreated, &user.ID, nil, logMeta("via", "portal_register")); err != nil {
		s.auditFail(w, err)
		return
	}
	s.provisionUser(r, provision.OpCreate, user, nil)

	if err := s.createPortalSession(w, r, user); err != nil {
		if errors.Is(err, errAuditUnavailable) {
			s.auditFail(w, err)
			return
		}
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/portal", http.StatusFound)
}

func (s *Server) handlePortalLoginPOST(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	password := r.FormValue("password")

	showErr := func(msg string) {
		s.ssoTmpl.render(w, "portal_login.html", struct {
			Error, Email  string
			AllowRegister bool
		}{msg, email, s.allowReg})
	}

	user, err := s.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !auth.CheckPassword(user.PasswordHash, password)) {
		if user != nil {
			s.incrementFailedAttempts(r, user)
		}
		if err := s.logAudit(r, ActionLoginFailed, nil, nil, logMeta("email", email, "via", "portal")); err != nil {
			s.auditFail(w, err)
			return
		}
		showErr("Invalid email or password.")
		return
	}
	if err != nil {
		s.log.Error("portal login lookup", "err", err)
		showErr("An error occurred. Please try again.")
		return
	}
	if !user.Active {
		showErr("Account is disabled.")
		return
	}

	pctx := policy.PolicyContext{User: user, Request: r}
	if v := s.policy.First(pctx); v != nil {
		showErr(v.Message)
		return
	}
	_ = s.store.UpdateUserFailedAttempts(r.Context(), user.ID, 0, nil)

	// Forced password rotation gates everything else — set by admin
	// reset actions (handlePortalAdminUserResetPassword,
	// handlePortalAdminUserCompromisedReset). Routes to the rotation
	// page BEFORE the MFA branch so the user can't MFA-verify and
	// avoid the rotation; the change-password handler resumes the
	// flow (MFA or direct session) once the rotation completes.
	if user.MustChangePassword {
		if err := s.setPortalLoginCookie(w, user.ID); err != nil {
			showErr("An error occurred. Please try again.")
			return
		}
		http.Redirect(w, r, "/portal/login/change-password", http.StatusFound)
		return
	}

	if user.MFAEnabled {
		// Send to TOTP MFA step.
		if err := s.setPortalLoginCookie(w, user.ID); err != nil {
			showErr("An error occurred. Please try again.")
			return
		}
		http.Redirect(w, r, "/portal/login/mfa", http.StatusFound)
		return
	}

	if err := s.createPortalSession(w, r, user); err != nil {
		if errors.Is(err, errAuditUnavailable) {
			s.auditFail(w, err)
			return
		}
		showErr("An error occurred. Please try again.")
		return
	}
	http.Redirect(w, r, "/portal", http.StatusFound)
}

// handlePortalChangePassword is the forced-rotation page. The user has
// already proved knowledge of the temp credential (via the password
// form before being redirected here), so we trust portalLoginCookie's
// identity assertion and just need to validate + persist the new
// password. After rotation, resume the original login flow — MFA prompt
// if enrolled, direct session otherwise.
//
// Defensive: re-check user.MustChangePassword on every request. If
// somebody navigates here directly with a stale cookie after they've
// already rotated, the cookie is valid but the user is no longer in
// the must-rotate state — we just clear the cookie and bounce them to
// /portal/login.
func (s *Server) handlePortalChangePassword(w http.ResponseWriter, r *http.Request) {
	st, err := s.getPortalLoginCookie(r)
	if err != nil {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), st.UserID)
	if err != nil {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	if !user.MustChangePassword {
		// Stale cookie; the rotation has already happened or was never
		// required. Clear and route to a fresh login.
		clearCookie(w, portalLoginCookie)
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}

	showForm := func(msg string) {
		s.ssoTmpl.render(w, "portal_change_password.html", struct {
			Error, Email string
		}{Error: msg, Email: user.Email})
	}

	if r.Method == http.MethodGet {
		showForm("")
		return
	}

	_ = r.ParseForm()
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm")
	if newPw == "" {
		showForm("New password is required.")
		return
	}
	if newPw != confirm {
		showForm("Passwords do not match.")
		return
	}
	if v := s.policy.First(policy.PolicyContext{Password: newPw, User: user, Request: r}); v != nil {
		showForm(v.Message)
		return
	}
	hash, err := auth.HashPassword(newPw)
	if err != nil {
		showForm("An error occurred. Please try again.")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), user.ID, hash); err != nil {
		s.log.Error("change-password update", "user", user.ID, "err", err)
		showForm("An error occurred. Please try again.")
		return
	}
	if err := s.logAudit(r, ActionUserUpdated, &user.ID, nil, logMeta("field", "password", "via", "forced_rotation")); err != nil {
		s.auditFail(w, err)
		return
	}
	// Reload to pick up the cleared must_change_password flag — the
	// subsequent MFA check + session creation expect the up-to-date
	// state.
	user, err = s.store.GetUserByID(r.Context(), user.ID)
	if err != nil {
		showForm("An error occurred. Please try again.")
		return
	}

	// Continue the original login flow exactly as handlePortalLoginPOST
	// would after a clean password validation.
	if user.MFAEnabled {
		// portalLoginCookie is already set with this user's ID — reuse
		// it as the MFA-pending cookie. (Both states are "password
		// verified, more steps required"; the cookie payload is
		// identical.)
		http.Redirect(w, r, "/portal/login/mfa", http.StatusFound)
		return
	}
	clearCookie(w, portalLoginCookie)
	if err := s.createPortalSession(w, r, user); err != nil {
		if errors.Is(err, errAuditUnavailable) {
			s.auditFail(w, err)
			return
		}
		showForm("An error occurred. Please try again.")
		return
	}
	http.Redirect(w, r, "/portal", http.StatusFound)
}

type mfaChoiceData struct {
	Error       string
	HasTOTP     bool
	HasWebAuthn bool
}

func (s *Server) portalMFAMethods(ctx context.Context, userID uuid.UUID) (hasTOTP, hasWebAuthn bool) {
	if totp, err := s.store.GetTOTPByUserID(ctx, userID); err == nil && totp.Enabled {
		hasTOTP = true
	}
	if waCreds, err := s.store.ListWebAuthnCredentials(ctx, userID); err == nil && len(waCreds) > 0 {
		hasWebAuthn = true
	}
	return
}

func (s *Server) handlePortalLoginMFA(w http.ResponseWriter, r *http.Request) {
	st, err := s.getPortalLoginCookie(r)
	if err != nil {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), st.UserID)
	if err != nil {
		http.Redirect(w, r, "/portal/login", http.StatusFound)
		return
	}
	// Belt-and-suspenders: if the user is in the must-rotate state,
	// MFA verification can't issue a session. Route to rotation first.
	// The login POST handler already does this gate before setting the
	// MFA-pending cookie, but a user with both flags set who navigates
	// directly here (or has a stale cookie from before flagged) needs
	// the redirect too.
	if user.MustChangePassword {
		http.Redirect(w, r, "/portal/login/change-password", http.StatusFound)
		return
	}
	hasTOTP, hasWebAuthn := s.portalMFAMethods(r.Context(), user.ID)

	showErr := func(msg string) {
		s.ssoTmpl.render(w, "portal_login_mfa.html", mfaChoiceData{
			Error: msg, HasTOTP: hasTOTP, HasWebAuthn: hasWebAuthn,
		})
	}

	if r.Method == http.MethodGet {
		s.ssoTmpl.render(w, "portal_login_mfa.html", mfaChoiceData{
			HasTOTP: hasTOTP, HasWebAuthn: hasWebAuthn,
		})
		return
	}

	_ = r.ParseForm()
	code := r.FormValue("code")
	if err := iMFA.VerifyTOTP(r.Context(), s.store, s.kp, user.ID, code); err != nil {
		if err := s.logAudit(r, ActionLoginMFAFailed, &user.ID, nil, logMeta("via", "portal")); err != nil {
			s.auditFail(w, err)
			return
		}
		showErr("Invalid code. Please try again.")
		return
	}

	clearCookie(w, portalLoginCookie)
	if err := s.createPortalSession(w, r, user); err != nil {
		if errors.Is(err, errAuditUnavailable) {
			s.auditFail(w, err)
			return
		}
		showErr("An error occurred. Please try again.")
		return
	}
	http.Redirect(w, r, "/portal", http.StatusFound)
}

func (s *Server) handlePortalLoginMFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	st, err := s.getPortalLoginCookie(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "no login session")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), st.UserID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user not found")
		return
	}
	optJSON, sessionID, err := s.wa.BeginLogin(r.Context(), user)
	if err != nil {
		s.log.Error("portal login webauthn begin", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "begin login failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"options":    json.RawMessage(optJSON),
		"session_id": sessionID,
	})
}

func (s *Server) handlePortalLoginMFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	st, err := s.getPortalLoginCookie(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "no login session")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), st.UserID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "user not found")
		return
	}
	sessionIDStr := r.URL.Query().Get("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session_id")
		return
	}
	if _, err := s.wa.FinishLogin(r.Context(), user, sessionID, r); err != nil {
		if err := s.logAudit(r, ActionLoginMFAFailed, &user.ID, nil, logMeta("via", "portal_webauthn")); err != nil {
			s.auditFail(w, err)
			return
		}
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "webauthn verification failed")
		return
	}
	clearCookie(w, portalLoginCookie)
	if err := s.createPortalSession(w, r, user); err != nil {
		if errors.Is(err, errAuditUnavailable) {
			s.auditFail(w, err)
			return
		}
		s.writeError(w, http.StatusInternalServerError, "server_error", "session creation failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"redirect_to": "/portal"})
}

func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	if pc := portalFromCtx(r); pc != nil {
		// Signing out of the IdP means signing out *everywhere*: broadcast
		// user-scoped (no sid) to every RP holding a session for this user,
		// THEN wipe every session at auth (portal + RP-side rows minted at
		// /token). Order matters — broadcastLogout's first query is
		// ListSessionClientIDsByUser, which returns nothing if the sessions
		// have already been deleted, so notifications never fire. RPs
		// receive a sub-only logout_token and run their sub-based deletion
		// path; sub-only rather than sid-scoped because RPs persist the id
		// of the RP-token session (created during /token exchange), which
		// is a different row from the portal session being closed here.
		s.broadcastLogout(r.Context(), r, pc.User.ID, "")
		_ = s.store.DeleteSessionsByUserID(r.Context(), pc.User.ID)
		// Best-effort: rows are already deleted by the time we audit, so an
		// audit failure can't roll back — fail-closed doesn't help here.
		// The originating intent is still worth recording so the journal
		// has a primary row for the logout, not just the cross-RP fan-out.
		_ = s.logAudit(r, ActionLogout, &pc.User.ID, nil, logMeta("via", "portal"))
	}
	clearCookie(w, portalCookie)
	http.Redirect(w, r, "/portal/login", http.StatusFound)
}

// ensurePortalCookie creates a portal session row and sets the auth_portal
// cookie. Called from /authorize success paths so a user who authenticates
// at the IdP for an RP also gets logged into auth's own portal — without
// this, the user would need to authenticate a second time at /portal/login
// even though they just proved their identity moments ago at /authorize,
// and silent SSO on the next RP visit would also fail (no cookie to read).
//
// User-switch cleanup: if the browser is presenting a valid cookie for a
// *different* user (e.g. user A signed in earlier, then user B authenticates
// in the same browser via vault SSO), wipe A's sessions across the whole
// stack first — delete every session row A holds at auth, and broadcast a
// user-scoped back-channel logout so every RP wipes A's local state too.
// Without this, A's session row was orphaned (no cookie pointed to it but
// the row lived until sweeper culled it) and A's vault token kept working.
//
// Differs from createPortalSession: it emits no audit event for the new
// login. The surrounding /authorize flow already audits ActionLogin with
// the RP's client_id; a second portal-scoped login event for the same
// human action would be noise. The cleanup branch does audit (via
// broadcastLogout's existing entries). Best-effort overall: a failure to
// seat the cookie is logged but does NOT abort the OIDC code issuance —
// the RP login still succeeds.
func (s *Server) ensurePortalCookie(w http.ResponseWriter, r *http.Request, user *model.User) {
	if prevSess, prevUser, _, err := s.readAuthPortalSession(r); err == nil && prevSess != nil && prevUser.ID != user.ID {
		// Browser-scoped switch: B just authenticated, A's row in this
		// browser is now orphaned and any RP sessions A had through this
		// browser should die with the switch. Broadcast first (while A's
		// sessions still exist for the client-id query), then delete.
		s.broadcastLogout(r.Context(), r, prevUser.ID, "")
		if err := s.store.DeleteSessionsByUserID(r.Context(), prevUser.ID); err != nil {
			s.log.Warn("ensure portal cookie: delete prior user sessions", "prev_user_id", prevUser.ID, "err", err)
		}
		// Primary audit row for the forced logout, tagging the actor (the
		// user who triggered the switch) so an operator can reconstruct
		// "A was logged out because B signed in on the same browser."
		_ = s.logAudit(r, ActionLogout, &prevUser.ID, nil,
			logMeta("via", "user_switch", "by", user.Email))
	}
	rawAccess, err := auth.GenerateRawToken()
	if err != nil {
		s.log.Warn("ensure portal cookie: generate access", "err", err)
		return
	}
	rawRefresh, err := auth.GenerateRawToken()
	if err != nil {
		s.log.Warn("ensure portal cookie: generate refresh", "err", err)
		return
	}
	scopes := []string{"portal"}
	if user.IsAdmin {
		scopes = append(scopes, "admin")
	}
	now := time.Now()
	sess := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		ClientID:         portalClientUUID,
		AccessTokenHash:  auth.HashToken(rawAccess),
		RefreshTokenHash: auth.HashToken(rawRefresh),
		Scopes:           scopes,
		AccessExpiresAt:  now.Add(portalCookieTTL),
		RefreshExpiresAt: now.Add(portalCookieTTL),
		MFAVerified:      user.MFAEnabled,
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		s.log.Warn("ensure portal cookie: create session", "err", err)
		return
	}
	if err := s.setPortalCookie(w, rawAccess, portalCookieTTL, portalCookie); err != nil {
		s.log.Warn("ensure portal cookie: seal cookie", "err", err)
	}
}

func (s *Server) createPortalSession(w http.ResponseWriter, r *http.Request, user *model.User) error {
	rawAccess, err := auth.GenerateRawToken()
	if err != nil {
		return err
	}
	rawRefresh, err := auth.GenerateRawToken()
	if err != nil {
		return err
	}
	scopes := []string{"portal"}
	if user.IsAdmin {
		scopes = append(scopes, "admin")
	}
	now := time.Now()
	sess := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		ClientID:         portalClientUUID,
		AccessTokenHash:  auth.HashToken(rawAccess),
		RefreshTokenHash: auth.HashToken(rawRefresh),
		Scopes:           scopes,
		// Portal sessions never use the refresh credential — the raw value is
		// not handed to the browser — but the column is NOT NULL, so set it
		// to the same horizon as access to keep cleanup queries honest.
		AccessExpiresAt:  now.Add(portalCookieTTL),
		RefreshExpiresAt: now.Add(portalCookieTTL),
		MFAVerified:      user.MFAEnabled,
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		s.log.Error("create portal session", "err", err)
		return err
	}
	// Audit-then-cookie: if the journal is unreachable we leave the session row
	// in place (it expires on TTL) but never hand the cookie to the browser, so
	// the caller surfaces a 503 and the user cannot use the unaudited session.
	if err := s.logAudit(r, ActionLogin, &user.ID, nil, logMeta("via", "portal")); err != nil {
		return fmt.Errorf("%w: %v", errAuditUnavailable, err)
	}
	return s.setPortalCookie(w, rawAccess, portalCookieTTL, portalCookie)
}

// ── Portal home ───────────────────────────────────────────────────────────────

func (s *Server) handlePortalHome(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	s.portalTmpl.render(w, "portal_home.html", struct {
		portalBase
	}{newPortalBase(pc, "home")})
}

// ── Account / Profile (merged with MFA settings) ──────────────────────────────

// accountPageData drives portal_account.html. The Profile page hosts both the
// password/profile forms and the MFA enrollment cards (TOTP + WebAuthn) so a
// user has a single self-service surface.
type accountPageData struct {
	portalBase
	TOTPEnabled    bool
	TOTPEnrolling  bool
	OTPURI         string
	TOTPSecret     string
	WebAuthnCreds  []*model.WebAuthnCredential
	Success, Error string
}

func (s *Server) buildAccountPageData(r *http.Request, pc *portalCtx, success, errMsg string) accountPageData {
	totpCred, _ := s.store.GetTOTPByUserID(r.Context(), pc.User.ID)
	waCreds, _ := s.store.ListWebAuthnCredentials(r.Context(), pc.User.ID)
	tp := s.getTOTPPendingCookie(r)
	d := accountPageData{
		portalBase:    newPortalBase(pc, "account"),
		TOTPEnabled:   totpCred != nil && totpCred.Enabled,
		WebAuthnCreds: waCreds,
		Success:       success,
		Error:         errMsg,
	}
	if tp != nil {
		d.TOTPEnrolling = true
		d.OTPURI = tp.OTPURI
		d.TOTPSecret = tp.Secret
	}
	return d
}

func (s *Server) handlePortalAccount(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	d := s.buildAccountPageData(r, pc, r.URL.Query().Get("success"), r.URL.Query().Get("error"))
	s.portalTmpl.render(w, "portal_account.html", d)
}

func (s *Server) handlePortalAccountProfile(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		d := s.buildAccountPageData(r, pc, "", "Name cannot be empty.")
		s.portalTmpl.render(w, "portal_account.html", d)
		return
	}
	if err := s.store.UpdateUser(r.Context(), pc.User.ID, name, pc.User.Active); err != nil {
		s.log.Error("update profile", "err", err)
		http.Redirect(w, r, "/portal/account?error=update+failed", http.StatusFound)
		return
	}
	if err := s.logAudit(r, ActionUserUpdated, &pc.User.ID, nil, logMeta("field", "name")); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/account?success=Profile+updated.", http.StatusFound)
}

func (s *Server) handlePortalAccountPassword(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()

	showErr := func(msg string) {
		d := s.buildAccountPageData(r, pc, "", msg)
		s.portalTmpl.render(w, "portal_account.html", d)
	}

	currentPw := r.FormValue("current_password")
	newPw := r.FormValue("new_password")

	if !auth.CheckPassword(pc.User.PasswordHash, currentPw) {
		showErr("Current password is incorrect.")
		return
	}
	if v := s.policy.First(policy.PolicyContext{Password: newPw, Request: r}); v != nil {
		showErr(v.Message)
		return
	}
	hash, err := auth.HashPassword(newPw)
	if err != nil {
		showErr("An error occurred. Please try again.")
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), pc.User.ID, hash); err != nil {
		showErr("An error occurred. Please try again.")
		return
	}
	if err := s.logAudit(r, ActionUserUpdated, &pc.User.ID, nil, logMeta("field", "password")); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/account?success=Password+updated.", http.StatusFound)
}

func (s *Server) handlePortalMFATOTPEnroll(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	resp, err := iMFA.EnrollTOTP(r.Context(), s.store, s.kp, pc.User)
	if err != nil {
		s.log.Error("portal totp enroll", "err", err)
		http.Redirect(w, r, "/portal/account?error=enrollment+failed", http.StatusFound)
		return
	}
	if err := s.setTOTPPendingCookie(w, resp.OTPURI, resp.Secret); err != nil {
		http.Redirect(w, r, "/portal/account?error=enrollment+failed", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/portal/mfa", http.StatusFound)
}

func (s *Server) handlePortalMFATOTPConfirm(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	code := r.FormValue("code")
	if err := iMFA.ConfirmTOTP(r.Context(), s.store, s.kp, pc.User.ID, code); err != nil {
		http.Redirect(w, r, "/portal/account?error=Invalid+code.+Please+try+again.", http.StatusFound)
		return
	}
	if err := s.store.UpdateUserMFAEnabled(r.Context(), pc.User.ID, true); err != nil {
		s.log.Error("enable mfa", "err", err)
	}
	if err := s.logAudit(r, ActionMFATOTPEnrolled, &pc.User.ID, nil, nil); err != nil {
		s.auditFail(w, err)
		return
	}
	clearCookie(w, portalTOTPCookie)
	http.Redirect(w, r, "/portal/account?success=TOTP+enrolled+successfully.", http.StatusFound)
}

func (s *Server) handlePortalMFATOTPDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if err := s.store.DeleteTOTP(r.Context(), pc.User.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/portal/account?error=delete+failed", http.StatusFound)
		return
	}
	_ = s.store.UpdateUserMFAEnabled(r.Context(), pc.User.ID, false)
	if err := s.logAudit(r, ActionMFATOTPDeleted, &pc.User.ID, nil, nil); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/account?success=Authenticator+app+removed.", http.StatusFound)
}

// Portal WebAuthn registration (uses cookie-based portal session).
func (s *Server) handlePortalMFAWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	optJSON, sessionID, err := s.wa.BeginRegistration(r.Context(), pc.User)
	if err != nil {
		s.log.Error("portal webauthn begin", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"options":    json.RawMessage(optJSON),
		"session_id": sessionID,
	})
}

func (s *Server) handlePortalMFAWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	sessionIDStr := r.URL.Query().Get("session_id")
	deviceName := r.URL.Query().Get("device_name")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session_id")
		return
	}
	cred, err := s.wa.FinishRegistration(r.Context(), pc.User, sessionID, r, deviceName)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	_ = s.store.UpdateUserMFAEnabled(r.Context(), pc.User.ID, true)
	if err := s.logAudit(r, ActionMFAWebAuthnEnrolled, &pc.User.ID, nil, logMeta("credential_id", cred.ID)); err != nil {
		s.auditFail(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"id": cred.ID, "device_name": cred.DeviceName})
}

func (s *Server) handlePortalMFAWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	credIDStr := r.PathValue("id")
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		http.Redirect(w, r, "/portal/account?error=invalid+credential+id", http.StatusFound)
		return
	}
	if err := s.store.DeleteWebAuthnCredential(r.Context(), credID, pc.User.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/portal/account?error=credential+not+found", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/portal/account?error=delete+failed", http.StatusFound)
		return
	}
	creds, _ := s.store.ListWebAuthnCredentials(r.Context(), pc.User.ID)
	_, totpErr := s.store.GetTOTPByUserID(r.Context(), pc.User.ID)
	if len(creds) == 0 && totpErr != nil {
		_ = s.store.UpdateUserMFAEnabled(r.Context(), pc.User.ID, false)
	}
	if err := s.logAudit(r, ActionMFAWebAuthnDeleted, &pc.User.ID, nil, logMeta("credential_id", credID)); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/account?success=Security+key+removed.", http.StatusFound)
}

// ── Admin — Users ─────────────────────────────────────────────────────────────

func (s *Server) handlePortalAdminUsers(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		http.Error(w, "error listing users", http.StatusInternalServerError)
		return
	}
	s.portalTmpl.render(w, "portal_admin_users.html", struct {
		portalBase
		Users   []*model.User
		Success string
	}{newPortalBase(pc, "admin-users"), users, r.URL.Query().Get("success")})
}

// adminUserEditView feeds portal_admin_user_edit.html. It carries the form-state
// User, an IsNew flag, banner messages, and the full group catalogue with each
// row's IsMember pre-resolved so the template can render checkboxes without
// looking anything up. TempPW is populated after a Reset Password / Compromised
// Reset action — the template renders it once and the value is gone on the
// next request.
type adminUserEditView struct {
	portalBase
	User    *model.User
	IsNew   bool
	Error   string
	Success string
	TempPW  string
	Groups  []groupCheckbox
}

type groupCheckbox struct {
	ID          uuid.UUID
	DisplayName string
	IsMember    bool
}

// renderUserForm assembles the group checkbox list (selected reflects what
// should be checked, not what's currently in the DB — so POST handlers can
// preserve the user's submission on validation errors).
func (s *Server) renderUserForm(w http.ResponseWriter, r *http.Request, pc *portalCtx, u *model.User, isNew bool, errMsg, successMsg string, selected []uuid.UUID) {
	allGroups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.log.Error("admin user form: list groups", "err", err)
	}
	selSet := make(map[uuid.UUID]struct{}, len(selected))
	for _, id := range selected {
		selSet[id] = struct{}{}
	}
	checks := make([]groupCheckbox, len(allGroups))
	for i, g := range allGroups {
		_, in := selSet[g.ID]
		checks[i] = groupCheckbox{ID: g.ID, DisplayName: g.DisplayName, IsMember: in}
	}
	s.portalTmpl.render(w, "portal_admin_user_edit.html", adminUserEditView{
		portalBase: newPortalBase(pc, "admin-users"),
		User:       u,
		IsNew:      isNew,
		Error:      errMsg,
		Success:    successMsg,
		TempPW:     r.URL.Query().Get("temp_pw"),
		Groups:     checks,
	})
}

// currentMembershipFor returns the IDs of groups whose Members contain userID.
// Walks ListGroups in-process — fine while the group catalogue is small; revisit
// when N(groups) crosses ~10⁴.
func (s *Server) currentMembershipFor(ctx context.Context, userID uuid.UUID) []uuid.UUID {
	groups, _ := s.store.ListGroups(ctx)
	out := make([]uuid.UUID, 0)
	for _, g := range groups {
		if slices.Contains(g.Members, userID) {
			out = append(out, g.ID)
		}
	}
	return out
}

// syncUserGroups reconciles a user's group memberships to the `selected` set
// and fans the resulting per-group changes out to provisioners. Each group
// whose membership actually changed receives one provision.OpUpdate event with
// its post-change member list.
func (s *Server) syncUserGroups(r *http.Request, userID uuid.UUID, selected []uuid.UUID) {
	allGroups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.log.Error("sync user groups: list", "err", err)
		return
	}
	allUsers, _ := s.store.ListUsers(r.Context())
	selSet := make(map[uuid.UUID]struct{}, len(selected))
	for _, id := range selected {
		selSet[id] = struct{}{}
	}
	for _, g := range allGroups {
		wasMember := slices.Contains(g.Members, userID)
		_, isMember := selSet[g.ID]
		if wasMember == isMember {
			continue
		}
		if isMember {
			if err := s.store.AddGroupMember(r.Context(), g.ID, userID); err != nil {
				s.log.Error("sync user groups: add", "group", g.ID, "user", userID, "err", err)
				continue
			}
		} else {
			if err := s.store.RemoveGroupMember(r.Context(), g.ID, userID); err != nil {
				s.log.Error("sync user groups: remove", "group", g.ID, "user", userID, "err", err)
				continue
			}
		}
		fresh, err := s.store.GetGroupByID(r.Context(), g.ID)
		if err != nil {
			continue
		}
		s.provisionGroup(r, provision.OpUpdate, fresh, pickUsers(allUsers, fresh.Members))
	}
}

func parseGroupIDs(raw []string) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		if id, err := uuid.Parse(strings.TrimSpace(s)); err == nil {
			out = append(out, id)
		}
	}
	return out
}

func (s *Server) handlePortalAdminUserNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if r.Method == http.MethodGet {
		s.renderUserForm(w, r, pc, &model.User{Active: true}, true, "", "", nil)
		return
	}
	_ = r.ParseForm()

	formUser := &model.User{
		Name:    r.FormValue("name"),
		Email:   r.FormValue("email"),
		Active:  r.FormValue("active") == "1",
		IsAdmin: r.FormValue("is_admin") == "1",
	}
	groupIDs := parseGroupIDs(r.Form["group_ids"])

	showErr := func(msg string) {
		s.renderUserForm(w, r, pc, formUser, true, msg, "", groupIDs)
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")

	if email == "" || name == "" || password == "" {
		showErr("Email, name, and password are required.")
		return
	}
	if v := s.policy.First(policy.PolicyContext{Password: password, Request: r}); v != nil {
		showErr(v.Message)
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		showErr("An error occurred.")
		return
	}
	user, err := s.store.CreateUser(r.Context(), email, hash, name)
	if err != nil {
		if err == store.ErrConflict {
			showErr("A user with that email already exists.")
			return
		}
		showErr("An error occurred.")
		return
	}
	if !formUser.Active {
		_ = s.store.SetUserActive(r.Context(), user.ID, false)
	}
	if formUser.IsAdmin {
		_ = s.store.SetUserAdmin(r.Context(), user.ID, true)
	}
	s.syncUserGroups(r, user.ID, groupIDs)
	if err := s.logAudit(r, ActionUserCreated, &user.ID, nil, logMeta("email", email, "by", pc.User.Email, "groups", len(groupIDs))); err != nil {
		s.auditFail(w, err)
		return
	}
	user, _ = s.store.GetUserByID(r.Context(), user.ID)
	s.provisionUser(r, provision.OpCreate, user, nil)
	http.Redirect(w, r, "/portal/admin/users?success=User+created.", http.StatusFound)
}

func (s *Server) handlePortalAdminUserEdit(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	user, err := s.store.GetUserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		s.renderUserForm(w, r, pc, user, false,
			r.URL.Query().Get("error"), r.URL.Query().Get("success"),
			s.currentMembershipFor(r.Context(), id))
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	active := r.FormValue("active") == "1"
	isAdmin := r.FormValue("is_admin") == "1"
	groupIDs := parseGroupIDs(r.Form["group_ids"])

	showErr := func(msg string) {
		// Echo back what the admin typed; group selection reflects their submission, not the DB.
		formUser := *user
		formUser.Name = name
		formUser.Active = active
		formUser.IsAdmin = isAdmin
		s.renderUserForm(w, r, pc, &formUser, false, msg, "", groupIDs)
	}

	if name == "" {
		showErr("Name cannot be empty.")
		return
	}
	if err := s.store.UpdateUser(r.Context(), id, name, active); err != nil {
		showErr("Update failed.")
		return
	}
	if err := s.store.SetUserAdmin(r.Context(), id, isAdmin); err != nil {
		showErr("Update failed.")
		return
	}
	s.syncUserGroups(r, id, groupIDs)
	if err := s.logAudit(r, ActionUserUpdated, &id, nil, logMeta("by", pc.User.Email)); err != nil {
		s.auditFail(w, err)
		return
	}
	updated, _ := s.store.GetUserByID(r.Context(), id)
	if updated != nil {
		op := provision.OpUpdate
		if !active {
			op = provision.OpDeactivate
		}
		s.provisionUser(r, op, updated, nil)
	}
	http.Redirect(w, r, "/portal/admin/users?success=User+updated.", http.StatusFound)
}

// handlePortalAdminUserResetPassword issues a single-use temporary
// password (server-generated, 32 chars) and flips the user's
// must_change_password flag. The temp credential is shown once in the
// redirect's success banner and shared out-of-band by the admin
// (Slack, phone call, etc.); on next login the user is forced through
// /portal/login/change-password to set a real password before the
// session is issued.
//
// Compared to admin-typed temp passwords (the previous behavior),
// server-generation removes the operator-picks-a-weak-password class
// of mistakes and matches the "shown once" UX already used for OAuth
// client secret rotation.
//
// Audit: ActionUserUpdated with field=password, via=admin_reset so the
// trail distinguishes admin overrides from user-driven changes.
func (s *Server) handlePortalAdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	editURL := "/portal/admin/users/" + id.String() + "/edit"
	redirect := func(qs string) { http.Redirect(w, r, editURL+"?"+qs, http.StatusFound) }

	tempPw, err := auth.GenerateRawToken()
	if err != nil {
		redirect("error=" + url.QueryEscape("An error occurred generating the temp password."))
		return
	}
	hash, err := auth.HashPassword(tempPw)
	if err != nil {
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), id, hash); err != nil {
		s.log.Error("admin reset password: update", "user", id, "err", err)
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}
	// UpdateUserPassword clears must_change_password as part of its
	// statement (any successful password change un-expires). Flip it
	// back ON now so the temp credential cannot be used as a
	// long-lived password — the user must rotate it on first use.
	if err := s.store.SetUserMustChangePassword(r.Context(), id, true); err != nil {
		s.log.Error("admin reset password: set flag", "user", id, "err", err)
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}
	// User-scoped back-channel logout: every RP that holds a session
	// for this user is told to wipe its local state too. Must run
	// BEFORE DeleteSessionsByUserID — broadcastLogout's first query is
	// ListSessionClientIDsByUser, which returns nothing once sessions
	// are gone.
	s.broadcastLogout(r.Context(), r, id, "")
	_ = s.store.DeleteSessionsByUserID(r.Context(), id)
	if err := s.logAudit(r, ActionUserUpdated, &id, nil,
		logMeta("field", "password", "by", pc.User.Email, "via", "admin_reset")); err != nil {
		s.auditFail(w, err)
		return
	}
	// Surface the temp password in a dedicated query param the edit
	// page renders ONCE (analogous to OAuth client secret rotation).
	redirect("temp_pw=" + url.QueryEscape(tempPw))
}

// handlePortalAdminUserCompromisedReset is the "assume the worst" admin
// action. Bundles every credential-invalidation primitive into a single
// click for the lost-laptop / suspected-breach scenario:
//
//  1. Generate a single-use temp password, persist + flip
//     must_change_password (same mechanism as Reset Password — user
//     forced through rotation on next login).
//  2. Delete TOTP + every WebAuthn credential. The user must re-enroll
//     MFA from scratch; previously-trusted devices are no longer trusted.
//  3. Flip MFAEnabled=false so the rotation flow doesn't try to MFA
//     against the now-empty credential set.
//  4. Broadcast back-channel logout to every RP holding a session for
//     this user, then delete auth-side sessions.
//  5. Revoke active AWS STS sessions via the awsfed provisioner (same
//     code path as the per-user Revoke AWS Sessions button).
//  6. Audit ActionUserCompromisedReset with a single metadata-rich row
//     covering targets cleared.
//
// The temp password is surfaced in the redirect's temp_pw query — same
// pattern as Reset Password. Account stays Active=true; the user can
// authenticate and re-establish their state via the forced flows.
// Choose "Delete user" if full account lockoff is needed instead.
func (s *Server) handlePortalAdminUserCompromisedReset(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	editURL := "/portal/admin/users/" + id.String() + "/edit"
	redirect := func(qs string) { http.Redirect(w, r, editURL+"?"+qs, http.StatusFound) }

	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		redirect("error=" + url.QueryEscape("user not found"))
		return
	}

	// (1) Temp password + must-rotate.
	tempPw, err := auth.GenerateRawToken()
	if err != nil {
		redirect("error=" + url.QueryEscape("An error occurred generating the temp password."))
		return
	}
	hash, err := auth.HashPassword(tempPw)
	if err != nil {
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), id, hash); err != nil {
		s.log.Error("compromised reset: update password", "user", id, "err", err)
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}
	if err := s.store.SetUserMustChangePassword(r.Context(), id, true); err != nil {
		s.log.Error("compromised reset: set flag", "user", id, "err", err)
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}

	// (2) MFA wipe. TOTP first, then every WebAuthn credential.
	// Best-effort — log but don't abort if a single credential delete
	// fails; the overall bundled action remains valuable even if one
	// piece couldn't be cleared.
	totpCleared := false
	if err := s.store.DeleteTOTP(r.Context(), id); err == nil {
		totpCleared = true
	} else if !errors.Is(err, store.ErrNotFound) {
		s.log.Error("compromised reset: delete totp", "user", id, "err", err)
	}
	waCreds, _ := s.store.ListWebAuthnCredentials(r.Context(), id)
	waCleared := 0
	for _, c := range waCreds {
		if err := s.store.DeleteWebAuthnCredential(r.Context(), c.ID, id); err != nil {
			s.log.Error("compromised reset: delete webauthn", "user", id, "cred", c.ID, "err", err)
			continue
		}
		waCleared++
	}

	// (3) Flip MFAEnabled=false. The user re-enrolls if policy requires
	// MFA — the forced-rotation flow doesn't gate on this directly, but
	// keeping MFAEnabled=true with no credentials would make subsequent
	// logins infinite-loop on the MFA page.
	_ = s.store.UpdateUserMFAEnabled(r.Context(), id, false)

	// (4) Auth sessions + RP notifications. Same order as the password-
	// reset and user-delete paths: broadcast BEFORE delete so the
	// client-id query still finds rows.
	s.broadcastLogout(r.Context(), r, id, "")
	_ = s.store.DeleteSessionsByUserID(r.Context(), id)

	// (5) AWS federation revocation. Walks the registry for awsfed
	// provisioners. No-op when no aws_federation integration is
	// enabled; logged as 0 in the audit metadata so investigators can
	// tell whether AWS was in scope.
	awsTargets := 0
	if s.provReg != nil {
		for _, prov := range s.provReg.Snapshot() {
			fed, ok := prov.(*awsfed.Provisioner)
			if !ok {
				continue
			}
			if err := fed.RevokeUser(r.Context(), user.ID.String()); err != nil {
				s.log.Error("compromised reset: aws revoke", "user", id, "target", fed.Name(), "err", err)
				continue
			}
			awsTargets++
		}
	}

	// (6) Single audit row covering the whole bundle. Investigators
	// looking at "what did this admin do" see one event with the full
	// scope, not five tangentially-related rows.
	if err := s.logAudit(r, ActionUserCompromisedReset, &id, nil, logMeta(
		"by", pc.User.Email,
		"totp_cleared", totpCleared,
		"webauthn_cleared", waCleared,
		"aws_targets_revoked", awsTargets,
	)); err != nil {
		s.auditFail(w, err)
		return
	}
	redirect("temp_pw=" + url.QueryEscape(tempPw))
}

// handlePortalAdminUserClearMFA deletes every MFA credential (TOTP + WebAuthn)
// belonging to the target user and flips MFAEnabled off. One audit row per
// credential, plus the standard `by=<admin>` provenance.
func (s *Server) handlePortalAdminUserClearMFA(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	editURL := "/portal/admin/users/" + id.String() + "/edit"

	switch err := s.store.DeleteTOTP(r.Context(), id); {
	case err == nil:
		if auditErr := s.logAudit(r, ActionMFATOTPDeleted, &id, nil, logMeta("by", pc.User.Email)); auditErr != nil {
			s.auditFail(w, auditErr)
			return
		}
	case errors.Is(err, store.ErrNotFound):
		// Nothing to delete.
	default:
		s.log.Error("admin clear totp", "user", id, "err", err)
	}

	creds, _ := s.store.ListWebAuthnCredentials(r.Context(), id)
	for _, c := range creds {
		if err := s.store.DeleteWebAuthnCredential(r.Context(), c.ID, id); err != nil {
			s.log.Error("admin delete webauthn", "user", id, "cred", c.ID, "err", err)
			continue
		}
		// Stop on first audit failure: better to leave the remaining credentials
		// in place (admin can retry once NATS is back) than to silently delete
		// without an audit row for any of them.
		if err := s.logAudit(r, ActionMFAWebAuthnDeleted, &id, nil, logMeta("credential_id", c.ID, "by", pc.User.Email)); err != nil {
			s.auditFail(w, err)
			return
		}
	}
	_ = s.store.UpdateUserMFAEnabled(r.Context(), id, false)
	http.Redirect(w, r, editURL+"?success="+url.QueryEscape("MFA credentials cleared."), http.StatusFound)
}

// handlePortalAdminUserRevokeAWS pushes the target user onto every AWS
// federation role's AuthRevokedUsers inline policy, killing their
// current STS sessions within ~30s. Does NOT deactivate the user — they
// can re-authenticate to auth and federate again immediately. This is
// the "Revoke AWS sessions" button on the user edit page; the right
// action for lost-laptop / suspect-credential-leak scenarios where you
// want to invalidate stale credentials but not lock the account.
//
// No-op when no aws_federation provisioner is enabled in the registry
// — the operator sees an informational notice. Federation roles that
// aren't auth-managed (no aws_federation integration row covers them)
// are similarly not touched; only roles auth knows about get the deny.
func (s *Server) handlePortalAdminUserRevokeAWS(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	editURL := "/portal/admin/users/" + id.String() + "/edit"
	redirect := func(qs string) { http.Redirect(w, r, editURL+"?"+qs, http.StatusFound) }

	user, err := s.store.GetUserByID(r.Context(), id)
	if err != nil {
		redirect("error=" + url.QueryEscape("user not found"))
		return
	}

	if s.provReg == nil {
		redirect("error=" + url.QueryEscape("provisioner registry not configured"))
		return
	}
	// Walk the snapshot for awsfed provisioners and call RevokeUser on
	// each. The same pattern as the reaper in cmd/authd. Multiple
	// aws_federation rows are unusual but supported — each manages its
	// own set of roles via the shared aws_roles table, so revoking the
	// user across all of them is the right semantic.
	revokedTargets := 0
	var firstErr error
	for _, prov := range s.provReg.Snapshot() {
		fed, ok := prov.(*awsfed.Provisioner)
		if !ok {
			continue
		}
		if err := fed.RevokeUser(r.Context(), user.ID.String()); err != nil {
			s.log.Error("admin revoke aws", "user", user.ID, "target", fed.Name(), "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		revokedTargets++
	}

	if revokedTargets == 0 && firstErr == nil {
		// Surfaces via the existing error= channel — phrased as a config
		// guidance message rather than a failure, but the user clicked a
		// button that did nothing useful, which is what they need to know.
		redirect("error=" + url.QueryEscape("No AWS federation integration is enabled; nothing to revoke. Enable one under /portal/admin/integrations."))
		return
	}
	if err := s.logAudit(r, ActionAWSFederationRevokedManual, &user.ID, nil,
		logMeta("by", pc.User.Email, "targets_revoked", revokedTargets, "any_error", firstErr != nil)); err != nil {
		s.auditFail(w, err)
		return
	}
	if firstErr != nil {
		// Partial success — some targets succeeded. The user's UUID is
		// on those roles' deny lists; the reaper will eventually trim
		// it. Failed targets can be retried by clicking again.
		redirect("error=" + url.QueryEscape(fmt.Sprintf("Revoked on %d target(s); some failed — see logs.", revokedTargets)))
		return
	}
	redirect("success=" + url.QueryEscape(fmt.Sprintf("AWS sessions revoked across %d target(s). Existing STS credentials will start failing within ~30 seconds.", revokedTargets)))
}

func (s *Server) handlePortalAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	user, _ := s.store.GetUserByID(r.Context(), id)
	// User is being removed wholesale — wipe RP-side sessions too. Must
	// run BEFORE DeleteSessionsByUserID so broadcastLogout's first query
	// (ListSessionClientIDsByUser) still finds the user's sessions.
	s.broadcastLogout(r.Context(), r, id, "")
	_ = s.store.DeleteSessionsByUserID(r.Context(), id)
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/users?error=delete+failed", http.StatusFound)
		return
	}
	if err := s.logAudit(r, ActionUserDeleted, &id, nil, logMeta("by", pc.User.Email)); err != nil {
		s.auditFail(w, err)
		return
	}
	if user != nil {
		s.provisionUser(r, provision.OpDelete, user, nil)
	}
	http.Redirect(w, r, "/portal/admin/users?success=User+deleted.", http.StatusFound)
}

// ── Admin — Clients ───────────────────────────────────────────────────────────

func (s *Server) handlePortalAdminClients(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	clients, _ := s.store.ListClients(r.Context())
	s.portalTmpl.render(w, "portal_admin_clients.html", struct {
		portalBase
		Clients                   []*model.Client
		Success, Error, NewSecret string
	}{newPortalBase(pc, "admin-clients"), clients, r.URL.Query().Get("success"), r.URL.Query().Get("error"), r.URL.Query().Get("secret")})
}

// adminClientEditView is the template data for new + edit client forms.
// Portal-visibility fields (ShowInPortal, LaunchURL, …) and the
// VisibilityGroups checkbox list power the new "Portal visibility"
// section on the form; existing fields are unchanged.
type adminClientEditView struct {
	portalBase
	Client           *model.Client
	IsNew            bool
	Error, NewSecret string
	VisibilityGroups []groupCheckbox // every SCIM group + an IsMember flag indicating "currently linked to this client"
}

// renderClientForm assembles VisibilityGroups from the full SCIM group
// list plus a selected-IDs set, so POST handlers can preserve the user's
// submission on validation errors without re-querying the DB-of-truth.
func (s *Server) renderClientForm(w http.ResponseWriter, r *http.Request, pc *portalCtx, cl *model.Client, isNew bool, errMsg, newSecret string, selectedGroupIDs []uuid.UUID) {
	allGroups, _ := s.store.ListGroups(r.Context())
	selSet := make(map[uuid.UUID]struct{}, len(selectedGroupIDs))
	for _, id := range selectedGroupIDs {
		selSet[id] = struct{}{}
	}
	checks := make([]groupCheckbox, len(allGroups))
	for i, g := range allGroups {
		_, in := selSet[g.ID]
		checks[i] = groupCheckbox{ID: g.ID, DisplayName: g.DisplayName, IsMember: in}
	}
	s.portalTmpl.render(w, "portal_admin_client_edit.html", adminClientEditView{
		portalBase:       newPortalBase(pc, "admin-clients"),
		Client:           cl,
		IsNew:            isNew,
		Error:            errMsg,
		NewSecret:        newSecret,
		VisibilityGroups: checks,
	})
}

func (s *Server) handlePortalAdminClientNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if r.Method == http.MethodGet {
		s.renderClientForm(w, r, pc, &model.Client{}, true, "", "", nil)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	public := r.FormValue("public") == "1"
	redirectURIs := parseLines(r.FormValue("redirect_uris"))
	scopes := strings.Fields(r.FormValue("scopes"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	var backchannelLogoutURI *string
	if v := strings.TrimSpace(r.FormValue("backchannel_logout_uri")); v != "" {
		backchannelLogoutURI = &v
	}
	showInPortal := r.FormValue("show_in_portal") == "1"
	launchURL := strings.TrimSpace(r.FormValue("launch_url"))
	brandColor := strings.TrimSpace(r.FormValue("brand_color"))
	iconURL := strings.TrimSpace(r.FormValue("icon_url"))
	visibleToAll := r.FormValue("visible_to_all") == "1"
	groupIDs := parseGroupIDs(r.Form["visibility_group_ids"])

	showErr := func(msg string) {
		cl := &model.Client{
			Name: name, RedirectURIs: redirectURIs, Scopes: scopes, Public: public,
			BackchannelLogoutURI: backchannelLogoutURI,
			ShowInPortal:         showInPortal, LaunchURL: launchURL, BrandColor: brandColor, IconURL: iconURL, VisibleToAll: visibleToAll,
		}
		s.renderClientForm(w, r, pc, cl, true, msg, "", groupIDs)
	}

	if name == "" {
		showErr("Name is required.")
		return
	}
	if showInPortal && launchURL == "" {
		showErr("Launch URL is required when the client is shown in the portal.")
		return
	}
	rawClientID, err := auth.GenerateRawToken()
	if err != nil {
		showErr("An error occurred.")
		return
	}
	clientID := rawClientID[:24]
	var secretHash, rawSecret string
	if !public {
		rawSecret, err = auth.GenerateRawToken()
		if err != nil {
			showErr("An error occurred.")
			return
		}
		secretHash = auth.HashToken(rawSecret)
	}
	client, err := s.store.CreateClient(r.Context(), clientID, secretHash, name, redirectURIs, scopes, public, backchannelLogoutURI)
	if err != nil {
		showErr("An error occurred.")
		return
	}
	// Portal config + visibility are persisted in two separate calls
	// (the column update and the join-table reset) — UpdateClient's
	// signature can't accept these without an additive refactor, so
	// the dedicated UpdateClientPortalConfig + ReplaceClientVisibility
	// methods carry the load. Both are no-ops when the operator left
	// the portal section unchecked.
	if err := s.store.UpdateClientPortalConfig(r.Context(), client.ID, showInPortal, launchURL, brandColor, iconURL, visibleToAll); err != nil {
		s.log.Error("set client portal config", "id", client.ID, "err", err)
	}
	if err := s.store.ReplaceClientVisibility(r.Context(), client.ID, groupIDs); err != nil {
		s.log.Error("set client visibility", "id", client.ID, "err", err)
	}
	if err := s.logAudit(r, ActionClientCreated, nil, &client.ID, logMeta("by", pc.User.Email, "portal_visible", showInPortal)); err != nil {
		s.auditFail(w, err)
		return
	}
	if rawSecret != "" {
		http.Redirect(w, r, "/portal/admin/clients?success=Client+created.&secret="+rawSecret, http.StatusFound)
	} else {
		http.Redirect(w, r, "/portal/admin/clients?success=Client+created.", http.StatusFound)
	}
}

func (s *Server) handlePortalAdminClientEdit(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	client, err := s.store.GetClientByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "client not found", http.StatusNotFound)
		return
	}

	if r.Method == http.MethodGet {
		current, _ := s.store.ListClientVisibility(r.Context(), id)
		s.renderClientForm(w, r, pc, client, false, "", "", current)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	redirectURIs := parseLines(r.FormValue("redirect_uris"))
	scopes := strings.Fields(r.FormValue("scopes"))
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}
	public := r.FormValue("public") == "1"
	var backchannelLogoutURI *string
	if v := strings.TrimSpace(r.FormValue("backchannel_logout_uri")); v != "" {
		backchannelLogoutURI = &v
	}
	showInPortal := r.FormValue("show_in_portal") == "1"
	launchURL := strings.TrimSpace(r.FormValue("launch_url"))
	brandColor := strings.TrimSpace(r.FormValue("brand_color"))
	iconURL := strings.TrimSpace(r.FormValue("icon_url"))
	visibleToAll := r.FormValue("visible_to_all") == "1"
	groupIDs := parseGroupIDs(r.Form["visibility_group_ids"])

	showErr := func(msg string) {
		// Echo back what the admin typed; visibility groups reflect their submission.
		formClient := *client
		formClient.Name = name
		formClient.RedirectURIs = redirectURIs
		formClient.Scopes = scopes
		formClient.Public = public
		formClient.BackchannelLogoutURI = backchannelLogoutURI
		formClient.ShowInPortal = showInPortal
		formClient.LaunchURL = launchURL
		formClient.BrandColor = brandColor
		formClient.IconURL = iconURL
		formClient.VisibleToAll = visibleToAll
		s.renderClientForm(w, r, pc, &formClient, false, msg, "", groupIDs)
	}

	if name == "" {
		showErr("Name is required.")
		return
	}
	if showInPortal && launchURL == "" {
		showErr("Launch URL is required when the client is shown in the portal.")
		return
	}
	if err := s.store.UpdateClient(r.Context(), id, name, redirectURIs, scopes, public, backchannelLogoutURI); err != nil {
		s.log.Error("update client", "id", id, "err", err)
		showErr("An error occurred. Please try again.")
		return
	}
	if err := s.store.UpdateClientPortalConfig(r.Context(), id, showInPortal, launchURL, brandColor, iconURL, visibleToAll); err != nil {
		s.log.Error("update client portal config", "id", id, "err", err)
		showErr("An error occurred. Please try again.")
		return
	}
	if err := s.store.ReplaceClientVisibility(r.Context(), id, groupIDs); err != nil {
		s.log.Error("update client visibility", "id", id, "err", err)
		showErr("An error occurred. Please try again.")
		return
	}
	if err := s.logAudit(r, ActionClientUpdated, nil, &id, logMeta("by", pc.User.Email, "portal_visible", showInPortal)); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/admin/clients?success=Client+details+saved.", http.StatusFound)
}

func (s *Server) handlePortalAdminClientDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteClient(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/clients?error=delete+failed", http.StatusFound)
		return
	}
	if err := s.logAudit(r, ActionClientDeleted, nil, &id, logMeta("by", pc.User.Email)); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/admin/clients?success=Client+deleted.", http.StatusFound)
}

func (s *Server) handlePortalAdminClientRotate(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/clients?error=invalid+id", http.StatusFound)
		return
	}
	client, err := s.store.GetClientByID(r.Context(), id)
	if err != nil {
		http.Redirect(w, r, "/portal/admin/clients?error=client+not+found", http.StatusFound)
		return
	}
	if client.Public {
		http.Redirect(w, r, "/portal/admin/clients?error=public+clients+have+no+secret", http.StatusFound)
		return
	}
	rawSecret, err := auth.GenerateRawToken()
	if err != nil {
		http.Redirect(w, r, "/portal/admin/clients?error=generation+failed", http.StatusFound)
		return
	}
	if err := s.store.UpdateClientSecret(r.Context(), id, auth.HashToken(rawSecret)); err != nil {
		http.Redirect(w, r, "/portal/admin/clients?error=update+failed", http.StatusFound)
		return
	}
	if err := s.logAudit(r, ActionClientSecretRotated, nil, &id, logMeta("by", pc.User.Email)); err != nil {
		s.auditFail(w, err)
		return
	}
	http.Redirect(w, r, "/portal/admin/clients?success=Secret+rotated.&secret="+rawSecret, http.StatusFound)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseLines(s string) []string {
	var out []string
	for line := range strings.SplitSeq(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
