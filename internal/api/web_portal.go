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
		_ = s.store.DeleteSession(r.Context(), pc.Session.ID)
		// Notify every RP that holds a session for this user. Session-scoped
		// so an RP can target the specific local session that maps to this
		// OP session id rather than killing all of the user's RP sessions.
		s.broadcastLogout(r.Context(), r, pc.User.ID, pc.Session.ID.String())
	}
	clearCookie(w, portalCookie)
	http.Redirect(w, r, "/portal/login", http.StatusFound)
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
// looking anything up.
type adminUserEditView struct {
	portalBase
	User    *model.User
	IsNew   bool
	Error   string
	Success string
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

// handlePortalAdminUserResetPassword lets an admin set a new password without
// knowing the current one. Audited the same way self-service password updates
// are (`field=password`) but with `by=<admin email>` so the trail distinguishes
// admin overrides from user-driven changes.
func (s *Server) handlePortalAdminUserResetPassword(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	newPw := r.FormValue("new_password")
	editURL := "/portal/admin/users/" + id.String() + "/edit"
	redirect := func(qs string) { http.Redirect(w, r, editURL+"?"+qs, http.StatusFound) }

	if newPw == "" {
		redirect("error=" + url.QueryEscape("Password is required."))
		return
	}
	if v := s.policy.First(policy.PolicyContext{Password: newPw, Request: r}); v != nil {
		redirect("error=" + url.QueryEscape(v.Message))
		return
	}
	hash, err := auth.HashPassword(newPw)
	if err != nil {
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}
	if err := s.store.UpdateUserPassword(r.Context(), id, hash); err != nil {
		redirect("error=" + url.QueryEscape("An error occurred."))
		return
	}
	// Force re-auth on every existing session — the old password no longer holds.
	_ = s.store.DeleteSessionsByUserID(r.Context(), id)
	// User-scoped back-channel logout: every RP that holds a session for
	// this user is told to wipe its local state too.
	s.broadcastLogout(r.Context(), r, id, "")
	if err := s.logAudit(r, ActionUserUpdated, &id, nil, logMeta("field", "password", "by", pc.User.Email)); err != nil {
		s.auditFail(w, err)
		return
	}
	redirect("success=" + url.QueryEscape("Password reset."))
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

func (s *Server) handlePortalAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	user, _ := s.store.GetUserByID(r.Context(), id)
	_ = s.store.DeleteSessionsByUserID(r.Context(), id)
	// User is being removed wholesale — wipe RP-side sessions too.
	s.broadcastLogout(r.Context(), r, id, "")
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

func (s *Server) handlePortalAdminClientNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if r.Method == http.MethodGet {
		s.portalTmpl.render(w, "portal_admin_client_edit.html", struct {
			portalBase
			Client           *model.Client
			IsNew            bool
			Error, NewSecret string
		}{newPortalBase(pc, "admin-clients"), &model.Client{}, true, "", ""})
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

	showErr := func(msg string) {
		cl := &model.Client{Name: name, RedirectURIs: redirectURIs, Scopes: scopes, Public: public, BackchannelLogoutURI: backchannelLogoutURI}
		s.portalTmpl.render(w, "portal_admin_client_edit.html", struct {
			portalBase
			Client           *model.Client
			IsNew            bool
			Error, NewSecret string
		}{newPortalBase(pc, "admin-clients"), cl, true, msg, ""})
	}

	if name == "" {
		showErr("Name is required.")
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
	if err := s.logAudit(r, ActionClientCreated, nil, &client.ID, logMeta("by", pc.User.Email)); err != nil {
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

	showErr := func(msg string) {
		s.portalTmpl.render(w, "portal_admin_client_edit.html", struct {
			portalBase
			Client           *model.Client
			IsNew            bool
			Error, NewSecret string
		}{newPortalBase(pc, "admin-clients"), client, false, msg, ""})
	}

	if r.Method == http.MethodGet {
		showErr("")
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		showErr("Name is required.")
		return
	}
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

	if err := s.store.UpdateClient(r.Context(), id, name, redirectURIs, scopes, public, backchannelLogoutURI); err != nil {
		s.log.Error("update client", "id", id, "err", err)
		showErr("An error occurred. Please try again.")
		return
	}
	if err := s.logAudit(r, ActionClientUpdated, nil, &id, logMeta("by", pc.User.Email)); err != nil {
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
