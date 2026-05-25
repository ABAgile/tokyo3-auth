package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	iMFA "github.com/abagile/tokyo3-auth/internal/mfa"
	"github.com/google/uuid"
)

// Step-up MFA: a click on a sensitive AWS role tile lands the user
// here when their session's last MFA challenge is stale (or never
// happened). The handler reuses the existing TOTP + WebAuthn factors
// the user enrolled at /portal/account; on success it stamps
// mfa_verified_at = now on the session row and dispatches to the
// originally-requested action via the `next` parameter.
//
// State carried on the URL:
//   next     — opaque action name (only "aws_console" today)
//   role_id  — UUID of the AWS role the user clicked
//
// All routes here run under portalAuth; they require an authenticated
// portal session already exists (the gate before step-up is reached).

// stepUpForm is the template payload for portal_step_up.html. Next and
// RoleID survive the GET → POST round trip via hidden form fields so a
// failed TOTP attempt re-renders without dropping the user's target.
type stepUpForm struct {
	Error       string
	Next        string
	RoleID      string
	HasTOTP     bool
	HasWebAuthn bool
}

// handlePortalStepUp serves both GET (render challenge) and POST
// (TOTP submission). WebAuthn is handled separately by the begin/finish
// pair below so the JS can drive it as an XHR sequence.
func (s *Server) handlePortalStepUp(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	_ = r.ParseForm()
	next := r.FormValue("next")
	if next == "" {
		next = r.URL.Query().Get("next")
	}
	roleID := r.FormValue("role_id")
	if roleID == "" {
		roleID = r.URL.Query().Get("role_id")
	}

	hasTOTP, hasWebAuthn := s.portalMFAMethods(r.Context(), pc.User.ID)
	if !hasTOTP && !hasWebAuthn {
		// A step-up gate the user can't satisfy: better to refuse
		// loudly at the launcher than to render a dead-end page.
		http.Redirect(w, r, "/portal/apps?error="+url.QueryEscape(
			"This action requires MFA, but no factors are enrolled on your account. Enroll one in /portal/account first."),
			http.StatusFound)
		return
	}

	render := func(errMsg string) {
		s.ssoTmpl.render(w, "portal_step_up.html", stepUpForm{
			Error: errMsg, Next: next, RoleID: roleID,
			HasTOTP: hasTOTP, HasWebAuthn: hasWebAuthn,
		})
	}

	if r.Method == http.MethodGet {
		render("")
		return
	}

	code := r.FormValue("code")
	if err := iMFA.VerifyTOTP(r.Context(), s.store, s.kp, pc.User.ID, code); err != nil {
		_ = s.logAudit(r, ActionLoginMFAFailed, &pc.User.ID, nil, logMeta("via", "step_up"))
		render("Invalid code. Please try again.")
		return
	}

	if err := s.markStepUpSuccess(r, pc); err != nil {
		s.log.Error("step-up mark session MFA", "err", err)
		render("Server error. Please try again.")
		return
	}
	dest, err := s.dispatchStepUpNext(r, pc, next, roleID)
	if err != nil {
		http.Redirect(w, r, "/portal/apps?error="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, dest, http.StatusFound)
}

// handlePortalStepUpWebAuthnBegin starts a WebAuthn assertion challenge
// for the currently signed-in portal user. Mirrors the /portal/login
// equivalent but reads the user from the portalCtx instead of the
// pre-login cookie.
func (s *Server) handlePortalStepUpWebAuthnBegin(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	optJSON, sessionID, err := s.wa.BeginLogin(r.Context(), pc.User)
	if err != nil {
		s.log.Error("step-up webauthn begin", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "begin login failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"options":    json.RawMessage(optJSON),
		"session_id": sessionID,
	})
}

// handlePortalStepUpWebAuthnFinish verifies the WebAuthn assertion,
// marks the session MFA, and returns the dispatched destination in
// JSON so the calling JS can navigate. next and role_id ride on the
// query string because the request body is the WebAuthn credential.
func (s *Server) handlePortalStepUpWebAuthnFinish(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	sessionIDStr := r.URL.Query().Get("session_id")
	sessionID, err := uuid.Parse(sessionIDStr)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request", "invalid session_id")
		return
	}
	if _, err := s.wa.FinishLogin(r.Context(), pc.User, sessionID, r); err != nil {
		_ = s.logAudit(r, ActionLoginMFAFailed, &pc.User.ID, nil, logMeta("via", "step_up_webauthn"))
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "webauthn verification failed")
		return
	}
	if err := s.markStepUpSuccess(r, pc); err != nil {
		s.log.Error("step-up webauthn mark session MFA", "err", err)
		s.writeError(w, http.StatusInternalServerError, "server_error", "mark session failed")
		return
	}
	dest, err := s.dispatchStepUpNext(r, pc, r.URL.Query().Get("next"), r.URL.Query().Get("role_id"))
	if err != nil {
		s.writeError(w, http.StatusBadGateway, "dispatch_failed", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"redirect_to": dest})
}

// markStepUpSuccess persists the MFA freshness update and mirrors it
// onto pc.Session so any downstream call that reads pc.Session in the
// same request (e.g. assumeRoleForUser, which emits the amr claim from
// sess.MFAVerified) sees the post-MFA state.
func (s *Server) markStepUpSuccess(r *http.Request, pc *portalCtx) error {
	now := time.Now()
	if err := s.store.MarkSessionMFA(r.Context(), pc.Session.ID, now); err != nil {
		return err
	}
	pc.Session.MFAVerified = true
	pc.Session.MFAVerifiedAt = &now
	return nil
}

// dispatchStepUpNext computes the post-MFA redirect destination based
// on the `next` action name. Returns an error when the action is
// recognised but cannot be completed (bad role_id, role no longer
// assigned, AWS-side failure); unknown/empty next falls back to the
// apps launcher so a user who navigated to /portal/step-up by hand
// still gets somewhere sensible after refreshing their MFA.
func (s *Server) dispatchStepUpNext(r *http.Request, pc *portalCtx, next, roleIDStr string) (string, error) {
	switch next {
	case "aws_console":
		roleID, err := uuid.Parse(roleIDStr)
		if err != nil {
			return "", errors.New("invalid role_id")
		}
		role, allowed, err := s.resolveAuthorizedAWSRole(r.Context(), pc.User.ID, roleID)
		if err != nil {
			return "", fmt.Errorf("role lookup failed: %w", err)
		}
		if !allowed {
			return "", errors.New("not authorized for that role")
		}
		return s.buildAWSConsoleURL(r, pc, role)
	default:
		return "/portal/apps", nil
	}
}
