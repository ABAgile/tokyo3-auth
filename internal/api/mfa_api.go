package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

// ── TOTP ─────────────────────────────────────────────────────────────────────

func (s *Server) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}
	resp, err := mfa.EnrollTOTP(r.Context(), s.store, s.kp, user)
	if err != nil {
		s.log.Error("totp enroll", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "enrollment failed")
		return
	}
	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "code required")
		return
	}
	if err := mfa.ConfirmTOTP(r.Context(), s.store, s.kp, sess.UserID, req.Code); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_code", err.Error())
		return
	}
	if err := s.store.UpdateUserMFAEnabled(r.Context(), sess.UserID, true); err != nil {
		s.log.Error("enable mfa", "err", err)
	}
	s.logAudit(r, ActionMFATOTPEnrolled, &sess.UserID, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "code required")
		return
	}
	if err := mfa.VerifyTOTP(r.Context(), s.store, s.kp, sess.UserID, req.Code); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_code", "invalid TOTP code")
		return
	}
	_ = s.store.UpdateSessionActivity(r.Context(), sess.ID, time.Now().UTC())
	s.writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}

func (s *Server) handleTOTPDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	if err := s.store.DeleteTOTP(r.Context(), sess.UserID); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusInternalServerError, "server_error", "delete failed")
		return
	}
	_ = s.store.UpdateUserMFAEnabled(r.Context(), sess.UserID, false)
	s.logAudit(r, ActionMFATOTPDeleted, &sess.UserID, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ── WebAuthn — registration (authenticated) ───────────────────────────────────

func (s *Server) handleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}
	optJSON, sessionID, err := s.wa.BeginRegistration(r.Context(), user)
	if err != nil {
		s.log.Error("webauthn begin register", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"options":    json.RawMessage(optJSON),
		"session_id": sessionID,
	})
}

func (s *Server) handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	sessionIDStr := r.URL.Query().Get("session_id")
	deviceName := r.URL.Query().Get("device_name")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session_id")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}
	cred, err := s.wa.FinishRegistration(r.Context(), user, sessionID, r, deviceName)
	if err != nil {
		s.log.Error("webauthn finish register", "err", err)
		s.writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	_ = s.store.UpdateUserMFAEnabled(r.Context(), sess.UserID, true)
	s.logAudit(r, ActionMFAWebAuthnEnrolled, &sess.UserID, nil, logMeta("credential_id", cred.ID))
	s.writeJSON(w, http.StatusOK, map[string]any{
		"id":          cred.ID,
		"device_name": cred.DeviceName,
	})
}

// ── WebAuthn — login (unauthenticated) ───────────────────────────────────────

func (s *Server) handleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "email required")
		return
	}
	user, err := s.store.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		// Don't leak user existence; return generic error
		s.writeError(w, http.StatusBadRequest, "invalid_request", "no WebAuthn credentials registered")
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
		"user_id":    user.ID,
	})
}

func (s *Server) handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	sessionIDStr := r.URL.Query().Get("session_id")
	userIDStr := r.URL.Query().Get("user_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid user_id")
		return
	}
	user, err := s.store.GetUserByID(r.Context(), userID)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "invalid_request", "user not found")
		return
	}
	_, err = s.wa.FinishLogin(r.Context(), user, sessionID, r)
	if err != nil {
		s.log.Error("webauthn finish login", "err", err)
		s.writeError(w, http.StatusUnauthorized, "invalid_request", "WebAuthn verification failed")
		return
	}
	s.logAudit(r, ActionLoginMFA, &user.ID, nil, logMeta("method", "webauthn"))
	s.writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}

func (s *Server) handleWebAuthnDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromCtx(r)
	credIDStr := r.PathValue("id")
	credID, err := uuid.Parse(credIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid credential id")
		return
	}
	if err := s.store.DeleteWebAuthnCredential(r.Context(), credID, sess.UserID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.writeError(w, http.StatusNotFound, "not_found", "credential not found")
			return
		}
		s.writeError(w, http.StatusInternalServerError, "server_error", "delete failed")
		return
	}
	// Disable MFA if no remaining WebAuthn creds and no TOTP
	creds, _ := s.store.ListWebAuthnCredentials(r.Context(), sess.UserID)
	_, totpErr := s.store.GetTOTPByUserID(r.Context(), sess.UserID)
	if len(creds) == 0 && totpErr != nil {
		_ = s.store.UpdateUserMFAEnabled(r.Context(), sess.UserID, false)
	}
	s.logAudit(r, ActionMFAWebAuthnDeleted, &sess.UserID, nil, logMeta("credential_id", credID))
	w.WriteHeader(http.StatusNoContent)
}
