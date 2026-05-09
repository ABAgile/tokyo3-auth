package api

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
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
	// Best-effort publish to JetStream. The local DB has already captured the
	// row; if NATS is offline we still have a record. Tighten to fail-closed
	// once the projection becomes the read source.
	if err := s.audit.Append(r.Context(), toAuditEntry(log)); err != nil {
		s.log.Error("audit publish failed", "action", action, "err", err)
	}
}

// toAuditEntry converts the internal model.AuditLog into the JetStream
// payload shape. UUIDs are formatted as canonical strings (or "" for nil),
// metadata is JSON-encoded once here so the consumer can store it verbatim,
// and OccurredAt falls back to time.Now() when the DB hasn't stamped the row.
func toAuditEntry(l *model.AuditLog) audit.Entry {
	var userID, clientID, metaJSON string
	if l.UserID != nil {
		userID = l.UserID.String()
	}
	if l.ClientID != nil {
		clientID = l.ClientID.String()
	}
	if len(l.Metadata) > 0 {
		if b, err := json.Marshal(l.Metadata); err == nil {
			metaJSON = string(b)
		}
	}
	occurred := l.CreatedAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}
	return audit.Entry{
		ID:         l.ID.String(),
		Action:     l.Action,
		UserID:     userID,
		ClientID:   clientID,
		IP:         l.IP,
		UserAgent:  l.UserAgent,
		Metadata:   metaJSON,
		OccurredAt: occurred,
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

func logMeta(kv ...any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}
