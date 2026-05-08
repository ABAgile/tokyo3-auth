package audit

import (
	"context"
	"time"
)

// Filter controls which audit log entries Store.ListAuditLogs returns.
type Filter struct {
	UserID   string // empty = all users (must be a canonical UUID string)
	ClientID string // empty = all clients (must be a canonical UUID string)
	Action   string // empty = all actions
	Limit    int    // 0 = default (50)
}

// Row is the projection-DB representation of a stored audit event. Fields are
// strings (not uuid.UUID) because the projection is intentionally decoupled
// from auth's domain model; the consumer binary only needs to insert and print
// rows, not to call business logic on them.
type Row struct {
	ID        string
	UserID    string // "" when the principal was anonymous
	ClientID  string // "" when the action wasn't tied to an OAuth2 client
	Action    string
	IP        string
	UserAgent string
	Metadata  string // JSON-encoded payload
	CreatedAt time.Time
}

// Store is the read/write interface for the audit database.
// Satisfied by *postgres.DB and *sqlite.DB.
type Store interface {
	UpsertAuditLog(ctx context.Context, e Entry) error
	ListAuditLogs(ctx context.Context, f Filter) ([]*Row, error)
	Close() error
}
