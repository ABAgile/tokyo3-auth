// Package audit provides the audit event pipeline for authd.
//
// Write path (authd serve):
//
//	Handler → Sink.Log → NATS JetStream "auth_audit" stream (authoritative record)
//
// Read/consume path (auth-audit — separate binary):
//
//	JetStream → auth-audit consume → DB.UpsertAuditLog → audit database
//	auth-audit query → DB.ListAuditLogs → terminal output
//
// The JetStream stream is the tamper-resistant, authoritative record (DenyDelete,
// DenyPurge, FileStorage). The audit database is a queryable projection rebuilt
// from the stream by auth-audit; it can be dropped and replayed at any time.
//
// Credential separation:
//   - authd serve uses a NATS publisher credential (PUBLISH-only on auth.audit.events).
//   - auth-audit consume uses a NATS consumer credential (SUBSCRIBE + consumer
//     management) and an audit DB writer credential (INSERT-only on audit_logs).
//   - Neither credential can perform the other role's operations.
package audit

import (
	"context"
	"time"
)

// Entry is the canonical shape of a single audit event. It is JSON-serialised
// as the NATS message payload and stored verbatim in the audit database by
// the consumer. Fields are omitted from JSON when empty to keep payloads lean.
//
// UserID and ClientID are formatted as canonical UUID strings (or "" when the
// principal is anonymous, e.g. failed-login attempts before user resolution).
// Metadata is a pre-serialised JSON object (or "" when empty); the publisher
// marshals the map[string]any into JSON before constructing the Entry so that
// the consumer can store it verbatim.
type Entry struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	UserID     string    `json:"user_id,omitempty"`
	ClientID   string    `json:"client_id,omitempty"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Metadata   string    `json:"metadata,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}

// Sink accepts audit events for durable, tamper-resistant storage.
// Log must be safe for concurrent callers. Close drains pending work and
// frees resources — call it on server shutdown.
type Sink interface {
	Log(ctx context.Context, e Entry) error
	Close() error
}

// NoopSink discards all events. Use in tests and when NATS is not configured.
type NoopSink struct{}

func (NoopSink) Log(_ context.Context, _ Entry) error { return nil }
func (NoopSink) Close() error                         { return nil }
