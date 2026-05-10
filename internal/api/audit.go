package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
	"github.com/google/uuid"
)

const (
	ActionLogin               = "auth.login"
	ActionLoginFailed         = "auth.login.failed"
	ActionLoginMFA            = "auth.login.mfa"
	ActionLoginMFAFailed      = "auth.login.mfa.failed"
	ActionLogout              = "auth.logout"
	ActionTokenIssued         = "auth.token.issued"
	ActionTokenRevoked        = "auth.token.revoked"
	ActionTokenRefreshed      = "auth.token.refreshed"
	ActionUserCreated         = "admin.user.created"
	ActionUserUpdated         = "admin.user.updated"
	ActionUserDeleted         = "admin.user.deleted"
	ActionClientCreated       = "admin.client.created"
	ActionClientUpdated       = "admin.client.updated"
	ActionClientDeleted       = "admin.client.deleted"
	ActionClientSecretRotated = "admin.client.secret.rotated"
	// Group lifecycle — managed via portal; fanned out to downstream SCIM/IAM provisioners.
	ActionGroupCreated        = "admin.group.created"
	ActionGroupUpdated        = "admin.group.updated"
	ActionGroupDeleted        = "admin.group.deleted"
	ActionMFATOTPEnrolled     = "mfa.totp.enrolled"
	ActionMFATOTPDeleted      = "mfa.totp.deleted"
	ActionMFAWebAuthnEnrolled = "mfa.webauthn.enrolled"
	ActionMFAWebAuthnDeleted  = "mfa.webauthn.deleted"
	ActionIntegrationCreated  = "admin.integration.created"
	ActionIntegrationUpdated  = "admin.integration.updated"
	ActionIntegrationDeleted  = "admin.integration.deleted"
	ActionIntegrationTested   = "admin.integration.tested"
	ActionIntegrationSynced   = "admin.integration.synced"
)

// logAudit publishes one audit event to the JetStream journal and returns
// any publish error to the caller. Fail-closed: if the journal is unreachable
// (NATS down, ack timeout, etc.) every handler that called logAudit must abort
// the originating request, because there is no longer a local DB mirror — an
// unjournalled event would be a compliance gap.
//
// Callers should treat any non-nil error as a hard 503 (or the form-handler
// equivalent) and never proceed with side effects beyond what already happened
// before this call. The action ordering rule across handlers therefore is:
// "audit last", so an audit failure surfaces as a failed response rather than
// a successful response with no audit row.
func (s *Server) logAudit(r *http.Request, action string, userID, clientID *uuid.UUID, meta map[string]any) error {
	var uID, cID, metaJSON string
	if userID != nil {
		uID = userID.String()
	}
	if clientID != nil {
		cID = clientID.String()
	}
	if len(meta) > 0 {
		if b, err := json.Marshal(meta); err == nil {
			metaJSON = string(b)
		}
	}
	entry := audit.Entry{
		ID:         uuid.New().String(),
		Action:     action,
		UserID:     uID,
		ClientID:   cID,
		IP:         clientIP(r),
		UserAgent:  r.Header.Get("User-Agent"),
		Metadata:   metaJSON,
		OccurredAt: time.Now().UTC(),
	}
	if err := s.audit.Append(r.Context(), entry); err != nil {
		s.log.Error("audit publish failed", "action", action, "err", err)
		return err
	}
	return nil
}

// auditFail writes a plain-text 503 — the uniform fail-closed response for
// every handler that called logAudit. Plain text (vs JSON) works for both
// browser-driven portal forms and programmatic API clients without per-handler
// branching. The message names the condition explicitly so an operator looking
// at a user-reported screenshot knows to check NATS rather than authd itself.
func (s *Server) auditFail(w http.ResponseWriter, err error) {
	http.Error(w, "audit journal unreachable; request refused: "+err.Error(), http.StatusServiceUnavailable)
}

// errAuditUnavailable wraps a logAudit error so callers downstream of helpers
// like createPortalSession can distinguish it from ordinary DB errors via
// errors.Is, even when the helper itself doesn't surface the responseWriter.
var errAuditUnavailable = errors.New("audit unavailable")

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, status int, errCode, desc string) {
	s.writeJSON(w, status, map[string]string{"error": errCode, "error_description": desc})
}

func logMeta(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}
