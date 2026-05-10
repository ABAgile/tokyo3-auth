package api

import (
	"net/http"
	"time"

	"github.com/abagile/tokyo3-base/journal/sse"
)

// handlePortalAdminAuditPage renders the audit-log shell — an empty table
// plus a small EventSource snippet that subscribes to /portal/admin/audit/sse
// and prepends each event as a row. Live data lives in NATS JetStream; this
// page is just the viewer.
func (s *Server) handlePortalAdminAuditPage(w http.ResponseWriter, r *http.Request) {
	pc := portalFromCtx(r)
	s.portalTmpl.render(w, "portal_admin_audit.html", struct {
		portalBase
	}{newPortalBase(pc, "admin-audit")})
}

// handlePortalAdminAuditSSE streams the JetStream audit subject to the
// browser. Replay window: 100. Heartbeat: 30s — under typical reverse-proxy
// idle thresholds. Reuses the singleton journal.Source held on Server, so
// every concurrent admin tab shares one NATS connection (one ephemeral
// JetStream consumer per tab).
func (s *Server) handlePortalAdminAuditSSE(w http.ResponseWriter, r *http.Request) {
	h := sse.Handler{
		Source:    s.auditSrc,
		Replay:    100,
		Heartbeat: 30 * time.Second,
	}
	h.ServeHTTP(w, r)
}
