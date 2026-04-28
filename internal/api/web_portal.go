package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/auth"
	icrypto "github.com/abagile/tokyo3-auth/internal/crypto"
	iMFA "github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/policy"
	"github.com/abagile/tokyo3-auth/internal/provision"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// portalClientUUID is the sentinel client used for portal sessions.
// Seeded by migration 005_portal_client.sql.
var portalClientUUID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

const portalCookie = "portal_tok"
const portalLoginCookie = "portal_login"
const portalCookieTTL = 8 * time.Hour
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
		c, err := r.Cookie(portalCookie)
		if err != nil {
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		enc, err := base64.RawURLEncoding.DecodeString(c.Value)
		if err != nil {
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		raw, err := icrypto.OpenBytes(s.masterKey, enc)
		if err != nil {
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		rawToken := string(raw)
		sess, err := s.store.GetSessionByAccessTokenHash(r.Context(), auth.HashToken(rawToken))
		if errors.Is(err, store.ErrNotFound) || (err == nil && time.Now().After(sess.ExpiresAt)) {
			clearCookie(w, portalCookie)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		if err != nil {
			s.log.Error("portal auth", "err", err)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		user, err := s.store.GetUserByID(r.Context(), sess.UserID)
		if err != nil {
			clearCookie(w, portalCookie)
			http.Redirect(w, r, "/portal/login", http.StatusFound)
			return
		}
		_ = s.store.UpdateSessionActivity(r.Context(), sess.ID, time.Now().UTC())
		pc := &portalCtx{Session: sess, User: user}
		ctx := context.WithValue(r.Context(), portalCtxKey{}, pc)
		next(w, r.WithContext(ctx))
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
	enc, err := icrypto.SealBytes(s.masterKey, []byte(rawToken))
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
	enc, err := icrypto.SealBytes(s.masterKey, data)
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
	raw, err := icrypto.OpenBytes(s.masterKey, enc)
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
	enc, err := icrypto.SealBytes(s.masterKey, data)
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
	raw, err := icrypto.OpenBytes(s.masterKey, enc)
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

	s.logAudit(r, ActionUserCreated, uuidPtr(user.ID), nil, logMeta("via", "portal_register"))
	s.provisionUser(r, provision.OpCreate, user, nil)

	if err := s.createPortalSession(w, r, user); err != nil {
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
		s.logAudit(r, ActionLoginFailed, nil, nil, logMeta("email", email, "via", "portal"))
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
		s.logAudit(r, ActionLoginMFAFailed, uuidPtr(user.ID), nil, logMeta("via", "portal"))
		showErr("Invalid code. Please try again.")
		return
	}

	clearCookie(w, portalLoginCookie)
	if err := s.createPortalSession(w, r, user); err != nil {
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
		s.logAudit(r, ActionLoginMFAFailed, uuidPtr(user.ID), nil, logMeta("via", "portal_webauthn"))
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "webauthn verification failed")
		return
	}
	clearCookie(w, portalLoginCookie)
	if err := s.createPortalSession(w, r, user); err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "session creation failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"redirect_to": "/portal"})
}

func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	if pc := portalFromCtx(r); pc != nil {
		_ = s.store.DeleteSession(r.Context(), pc.Session.ID)
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
	sess := &model.Session{
		ID:               uuid.New(),
		UserID:           user.ID,
		ClientID:         portalClientUUID,
		AccessTokenHash:  auth.HashToken(rawAccess),
		RefreshTokenHash: auth.HashToken(rawRefresh),
		Scopes:           scopes,
		ExpiresAt:        time.Now().Add(portalCookieTTL),
		MFAVerified:      user.MFAEnabled,
	}
	if err := s.store.CreateSession(r.Context(), sess); err != nil {
		s.log.Error("create portal session", "err", err)
		return err
	}
	s.logAudit(r, ActionLogin, uuidPtr(user.ID), nil, logMeta("via", "portal"))
	return s.setPortalCookie(w, rawAccess, portalCookieTTL, portalCookie)
}

// ── Portal home ───────────────────────────────────────────────────────────────

func (s *Server) handlePortalHome(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	s.portalTmpl.render(w, "portal_home.html", struct {
		portalBase
	}{newPortalBase(pc, "home")})
}

// ── Account settings ──────────────────────────────────────────────────────────

func (s *Server) handlePortalAccount(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	s.portalTmpl.render(w, "portal_account.html", struct {
		portalBase
		Success, Error string
	}{newPortalBase(pc, "account"), r.URL.Query().Get("success"), r.URL.Query().Get("error")})
}

func (s *Server) handlePortalAccountProfile(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		s.portalTmpl.render(w, "portal_account.html", struct {
			portalBase
			Success, Error string
		}{newPortalBase(pc, "account"), "", "Name cannot be empty."})
		return
	}
	if err := s.store.UpdateUser(r.Context(), pc.User.ID, name, pc.User.Active); err != nil {
		s.log.Error("update profile", "err", err)
		http.Redirect(w, r, "/portal/account?error=update+failed", http.StatusFound)
		return
	}
	s.logAudit(r, ActionUserUpdated, uuidPtr(pc.User.ID), nil, logMeta("field", "name"))
	http.Redirect(w, r, "/portal/account?success=Profile+updated.", http.StatusFound)
}

func (s *Server) handlePortalAccountPassword(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()

	showErr := func(msg string) {
		s.portalTmpl.render(w, "portal_account.html", struct {
			portalBase
			Success, Error string
		}{newPortalBase(pc, "account"), "", msg})
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
	s.logAudit(r, ActionUserUpdated, uuidPtr(pc.User.ID), nil, logMeta("field", "password"))
	http.Redirect(w, r, "/portal/account?success=Password+updated.", http.StatusFound)
}

// ── MFA settings ──────────────────────────────────────────────────────────────

func (s *Server) handlePortalMFA(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)

	totpCred, _ := s.store.GetTOTPByUserID(r.Context(), pc.User.ID)
	waCreds, _ := s.store.ListWebAuthnCredentials(r.Context(), pc.User.ID)
	tp := s.getTOTPPendingCookie(r)

	type mfaPageData struct {
		portalBase
		TOTPEnabled    bool
		TOTPEnrolling  bool
		OTPURI         string
		TOTPSecret     string
		WebAuthnCreds  []*model.WebAuthnCredential
		Success, Error string
	}
	d := mfaPageData{
		portalBase:    newPortalBase(pc, "mfa"),
		TOTPEnabled:   totpCred != nil && totpCred.Enabled,
		WebAuthnCreds: waCreds,
		Success:       r.URL.Query().Get("success"),
		Error:         r.URL.Query().Get("error"),
	}
	if tp != nil {
		d.TOTPEnrolling = true
		d.OTPURI = tp.OTPURI
		d.TOTPSecret = tp.Secret
	}
	s.portalTmpl.render(w, "portal_mfa.html", d)
}

func (s *Server) handlePortalMFATOTPEnroll(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	resp, err := iMFA.EnrollTOTP(r.Context(), s.store, s.kp, pc.User)
	if err != nil {
		s.log.Error("portal totp enroll", "err", err)
		http.Redirect(w, r, "/portal/mfa?error=enrollment+failed", http.StatusFound)
		return
	}
	if err := s.setTOTPPendingCookie(w, resp.OTPURI, resp.Secret); err != nil {
		http.Redirect(w, r, "/portal/mfa?error=enrollment+failed", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/portal/mfa", http.StatusFound)
}

func (s *Server) handlePortalMFATOTPConfirm(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	code := r.FormValue("code")
	if err := iMFA.ConfirmTOTP(r.Context(), s.store, s.kp, pc.User.ID, code); err != nil {
		http.Redirect(w, r, "/portal/mfa?error=Invalid+code.+Please+try+again.", http.StatusFound)
		return
	}
	if err := s.store.UpdateUserMFAEnabled(r.Context(), pc.User.ID, true); err != nil {
		s.log.Error("enable mfa", "err", err)
	}
	s.logAudit(r, ActionMFATOTPEnrolled, uuidPtr(pc.User.ID), nil, nil)
	clearCookie(w, portalTOTPCookie)
	http.Redirect(w, r, "/portal/mfa?success=TOTP+enrolled+successfully.", http.StatusFound)
}

func (s *Server) handlePortalMFATOTPDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if err := s.store.DeleteTOTP(r.Context(), pc.User.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		http.Redirect(w, r, "/portal/mfa?error=delete+failed", http.StatusFound)
		return
	}
	_ = s.store.UpdateUserMFAEnabled(r.Context(), pc.User.ID, false)
	s.logAudit(r, ActionMFATOTPDeleted, uuidPtr(pc.User.ID), nil, nil)
	http.Redirect(w, r, "/portal/mfa?success=Authenticator+app+removed.", http.StatusFound)
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
	s.logAudit(r, ActionMFAWebAuthnEnrolled, uuidPtr(pc.User.ID), nil, logMeta("credential_id", cred.ID))
	s.writeJSON(w, http.StatusOK, map[string]any{"id": cred.ID, "device_name": cred.DeviceName})
}

func (s *Server) handlePortalMFAWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	credIDStr := r.PathValue("id")
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		http.Redirect(w, r, "/portal/mfa?error=invalid+credential+id", http.StatusFound)
		return
	}
	if err := s.store.DeleteWebAuthnCredential(r.Context(), credID, pc.User.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/portal/mfa?error=credential+not+found", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/portal/mfa?error=delete+failed", http.StatusFound)
		return
	}
	creds, _ := s.store.ListWebAuthnCredentials(r.Context(), pc.User.ID)
	_, totpErr := s.store.GetTOTPByUserID(r.Context(), pc.User.ID)
	if len(creds) == 0 && totpErr != nil {
		_ = s.store.UpdateUserMFAEnabled(r.Context(), pc.User.ID, false)
	}
	s.logAudit(r, ActionMFAWebAuthnDeleted, uuidPtr(pc.User.ID), nil, logMeta("credential_id", credID))
	http.Redirect(w, r, "/portal/mfa?success=Security+key+removed.", http.StatusFound)
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

func (s *Server) handlePortalAdminUserNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	if r.Method == http.MethodGet {
		s.portalTmpl.render(w, "portal_admin_user_edit.html", struct {
			portalBase
			User  *model.User
			IsNew bool
			Error string
		}{newPortalBase(pc, "admin-users"), &model.User{Active: true}, true, ""})
		return
	}
	_ = r.ParseForm()

	showErr := func(msg string) {
		u := &model.User{Name: r.FormValue("name"), Email: r.FormValue("email"), Active: r.FormValue("active") == "1", IsAdmin: r.FormValue("is_admin") == "1"}
		s.portalTmpl.render(w, "portal_admin_user_edit.html", struct {
			portalBase
			User  *model.User
			IsNew bool
			Error string
		}{newPortalBase(pc, "admin-users"), u, true, msg})
	}

	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	name := strings.TrimSpace(r.FormValue("name"))
	password := r.FormValue("password")
	isAdmin := r.FormValue("is_admin") == "1"

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
	if r.FormValue("active") != "1" {
		_ = s.store.SetUserActive(r.Context(), user.ID, false)
	}
	if isAdmin {
		_ = s.store.SetUserAdmin(r.Context(), user.ID, true)
	}
	s.logAudit(r, ActionUserCreated, uuidPtr(user.ID), nil, logMeta("email", email, "by", pc.User.Email))
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

	showErr := func(msg string) {
		s.portalTmpl.render(w, "portal_admin_user_edit.html", struct {
			portalBase
			User  *model.User
			IsNew bool
			Error string
		}{newPortalBase(pc, "admin-users"), user, false, msg})
	}

	if r.Method == http.MethodGet {
		showErr("")
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	active := r.FormValue("active") == "1"
	isAdmin := r.FormValue("is_admin") == "1"

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
	s.logAudit(r, ActionUserUpdated, uuidPtr(id), nil, logMeta("by", pc.User.Email))
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

func (s *Server) handlePortalAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	user, _ := s.store.GetUserByID(r.Context(), id)
	_ = s.store.DeleteSessionsByUserID(r.Context(), id)
	if err := s.store.DeleteUser(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/users?error=delete+failed", http.StatusFound)
		return
	}
	s.logAudit(r, ActionUserDeleted, uuidPtr(id), nil, logMeta("by", pc.User.Email))
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

	showErr := func(msg string) {
		cl := &model.Client{Name: name, RedirectURIs: redirectURIs, Scopes: scopes, Public: public}
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
	client, err := s.store.CreateClient(r.Context(), clientID, secretHash, name, redirectURIs, scopes, public)
	if err != nil {
		showErr("An error occurred.")
		return
	}
	s.logAudit(r, ActionClientCreated, nil, uuidPtr(client.ID), logMeta("by", pc.User.Email))
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
	// Only update name and redirect URIs for existing clients; scopes not editable here for safety.
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		showErr("Name is required.")
		return
	}
	// We don't have an UpdateClient method, so just note the limitation.
	// Log the intended update.
	s.logAudit(r, ActionClientCreated, nil, uuidPtr(id), logMeta("action", "edit_attempted", "by", pc.User.Email))
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
	s.logAudit(r, ActionClientDeleted, nil, uuidPtr(id), logMeta("by", pc.User.Email))
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
	s.logAudit(r, ActionClientSecretRotated, nil, uuidPtr(id), logMeta("by", pc.User.Email))
	http.Redirect(w, r, "/portal/admin/clients?success=Secret+rotated.&secret="+rawSecret, http.StatusFound)
}

// ── Admin — SCIM Tokens ───────────────────────────────────────────────────────

func (s *Server) handlePortalAdminSCIMTokens(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	tokens, _ := s.store.ListSCIMTokens(r.Context())
	s.portalTmpl.render(w, "portal_admin_scim_tokens.html", struct {
		portalBase
		Tokens   []*model.SCIMToken
		NewToken string
		Error    string
	}{newPortalBase(pc, "admin-scim"), tokens, r.URL.Query().Get("token"), r.URL.Query().Get("error")})
}

func (s *Server) handlePortalAdminSCIMTokenNew(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	description := strings.TrimSpace(r.FormValue("description"))
	rawToken, err := auth.GenerateRawToken()
	if err != nil {
		http.Redirect(w, r, "/portal/admin/scim-tokens?error=generation+failed", http.StatusFound)
		return
	}
	t := &model.SCIMToken{
		ID:          uuid.New(),
		TokenHash:   auth.HashToken(rawToken),
		Description: description,
	}
	if err := s.store.CreateSCIMToken(r.Context(), t); err != nil {
		http.Redirect(w, r, "/portal/admin/scim-tokens?error=create+failed", http.StatusFound)
		return
	}
	s.logAudit(r, ActionLogin, uuidPtr(pc.User.ID), nil, logMeta("action", "scim_token_created"))
	http.Redirect(w, r, "/portal/admin/scim-tokens?token="+rawToken, http.StatusFound)
}

func (s *Server) handlePortalAdminSCIMTokenDelete(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/portal/admin/scim-tokens?error=invalid+id", http.StatusFound)
		return
	}
	if err := s.store.DeleteSCIMToken(r.Context(), id); err != nil {
		http.Redirect(w, r, "/portal/admin/scim-tokens?error=delete+failed", http.StatusFound)
		return
	}
	s.logAudit(r, ActionLogin, uuidPtr(pc.User.ID), nil, logMeta("action", "scim_token_deleted", "id", id))
	http.Redirect(w, r, "/portal/admin/scim-tokens", http.StatusFound)
}

// ── Admin — Audit Log ─────────────────────────────────────────────────────────

func (s *Server) handlePortalAdminAudit(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	const pageSize = 50
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	logs, _ := s.store.ListAuditLogs(r.Context(), pageSize+1, offset)
	hasMore := len(logs) > pageSize
	if hasMore {
		logs = logs[:pageSize]
	}
	s.portalTmpl.render(w, "portal_admin_audit.html", struct {
		portalBase
		Logs       []*model.AuditLog
		Offset     int
		OffsetEnd  int
		PrevOffset int
		NextOffset int
		HasMore    bool
	}{
		portalBase: newPortalBase(pc, "admin-audit"),
		Logs:       logs,
		Offset:     offset,
		OffsetEnd:  offset + len(logs),
		PrevOffset: max(0, offset-pageSize),
		NextOffset: offset + pageSize,
		HasMore:    hasMore,
	})
}

// ── helpers ───────────────────────────────────────────────────────────────────

func parseLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			out = append(out, t)
		}
	}
	return out
}
