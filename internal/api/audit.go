package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/model"
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
	ActionClientDeleted       = "admin.client.deleted"
	ActionClientSecretRotated = "admin.client.secret.rotated"
	ActionSCIMUserCreated     = "scim.user.created"
	ActionSCIMUserUpdated     = "scim.user.updated"
	ActionSCIMUserDeleted     = "scim.user.deleted"
	ActionSCIMGroupCreated    = "scim.group.created"
	ActionSCIMGroupUpdated    = "scim.group.updated"
	ActionSCIMGroupDeleted    = "scim.group.deleted"
	ActionMFATOTPEnrolled     = "mfa.totp.enrolled"
	ActionMFATOTPDeleted      = "mfa.totp.deleted"
	ActionMFAWebAuthnEnrolled = "mfa.webauthn.enrolled"
	ActionMFAWebAuthnDeleted  = "mfa.webauthn.deleted"
)

func (s *Server) logAudit(r *http.Request, action string, userID, clientID *uuid.UUID, meta map[string]any) {
	log := &model.AuditLog{
		ID:        uuid.New(),
		Action:    action,
		IP:        clientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
		UserID:    userID,
		ClientID:  clientID,
		Metadata:  meta,
	}
	if err := s.store.CreateAuditLog(r.Context(), log); err != nil {
		s.log.Error("audit log failed", "action", action, "err", err)
	}
}

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

func uuidPtr(id uuid.UUID) *uuid.UUID { return &id }

func logMeta(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}
