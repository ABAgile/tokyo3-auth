// Package audit provides the audit event types for authd.
//
// Write path (authd serve):
//
//	Handler → journal.EncodedSink[Entry].Append → JetStream "auth_audit"
//	                                              stream (authoritative store)
//
// Read paths (both off the same stream):
//
//	/portal/admin/audit/sse → journal/sse.Handler → live tail in browser
//	authd audit query       → journal/jetstream.Source → terminal output
//
// The JetStream stream is the tamper-resistant authoritative record
// (DenyDelete, DenyPurge, FileStorage, 13-month retention); there is no
// separate projection database. Querying back is a thin reader on top of
// journal.Source — same primitive both UI and CLI use.
//
// The Entry → JSON adapter and JetStream transport are provided by
// base/journal: authd wires up `journal.NewJSONSink[Entry](jetstreamInner)`
// and handlers call Append directly. Auth keeps only the Entry shape and
// the wire-config constants (Subject / StreamName / StreamMaxAge); the
// transport and the marshalling are not auth concerns.
package audit

import (
	"time"

	"github.com/abagile/tokyo3-base/journal"
)

// Wire-format constants for the audit journal. Subject is what authd
// publishes to; StreamName is the JetStream stream covering it. StreamMaxAge
// is the retention floor for PCI-DSS 10.5 (12 months); 13 months gives a
// comfortable roll-over buffer.
const (
	Subject      = "auth.audit.events"
	StreamName   = "auth_audit"
	StreamMaxAge = 400 * 24 * time.Hour
)

// Sink is a type alias for the typed JSON-encoding journal sink that authd
// uses to publish audit Entries. Construct with
// journal.NewJSONSink[Entry](innerSink) — the alias is purely an
// ergonomic shortcut, not a distinct type.
type Sink = *journal.EncodedSink[Entry]

// NoopSink is a shared audit sink that discards every event. Use in tests
// and dev environments where the audit journal is not configured. Safe for
// concurrent use; the underlying journal.NoopSink is stateless.
var NoopSink Sink = journal.NewJSONSink[Entry](journal.NoopSink{})

// Entry is the canonical shape of a single audit event. It is JSON-serialised
// as the journal payload and stored verbatim in the audit database by the
// consumer. Fields are omitted from JSON when empty to keep payloads lean.
//
// UserID and ClientID are formatted as canonical UUID strings (or "" when the
// principal is anonymous, e.g. failed-login attempts before user resolution).
// UserEmail/UserName/ClientName are denormalised name snapshots resolved at
// publish time so live tail viewers can render rows without a UUID-to-name
// round-trip — empty when the principal is anonymous or the row has been
// deleted before audit. Metadata is a pre-serialised JSON object (or ""
// when empty); the publisher marshals the map[string]any into JSON before
// constructing the Entry so that the consumer can store it verbatim.
type Entry struct {
	ID         string    `json:"id"`
	Action     string    `json:"action"`
	UserID     string    `json:"user_id,omitempty"`
	UserEmail  string    `json:"user_email,omitempty"`
	UserName   string    `json:"user_name,omitempty"`
	ClientID   string    `json:"client_id,omitempty"`
	ClientName string    `json:"client_name,omitempty"`
	IP         string    `json:"ip,omitempty"`
	UserAgent  string    `json:"user_agent,omitempty"`
	Metadata   string    `json:"metadata,omitempty"`
	OccurredAt time.Time `json:"occurred_at"`
}
