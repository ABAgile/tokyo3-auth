package audit_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
)

func TestEntry_JSONOmitsEmptyOptionalFields(t *testing.T) {
	e := audit.Entry{
		ID:         "evt-1",
		Action:     "auth.login",
		OccurredAt: time.Date(2026, 5, 17, 12, 0, 0, 0, time.UTC),
	}
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	required := []string{`"id":"evt-1"`, `"action":"auth.login"`, `"occurred_at":"2026-05-17T12:00:00Z"`}
	for _, frag := range required {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("missing fragment %q in %s", frag, raw)
		}
	}

	omitted := []string{`"user_id"`, `"user_email"`, `"client_id"`, `"metadata"`, `"ip"`, `"user_agent"`}
	for _, frag := range omitted {
		if strings.Contains(string(raw), frag) {
			t.Errorf("unexpected fragment %q in %s", frag, raw)
		}
	}
}

func TestEntry_JSONIncludesPopulatedFields(t *testing.T) {
	e := audit.Entry{
		ID:        "evt-2",
		Action:    "auth.token.issued",
		UserID:    "u-1",
		UserEmail: "alice@example.com",
		ClientID:  "c-1",
		IP:        "10.0.0.1",
		UserAgent: "TestClient/1.0",
		Metadata:  `{"foo":"bar"}`,
	}
	raw, _ := json.Marshal(e)
	for _, want := range []string{
		`"user_id":"u-1"`,
		`"user_email":"alice@example.com"`,
		`"client_id":"c-1"`,
		`"ip":"10.0.0.1"`,
		`"user_agent":"TestClient/1.0"`,
		`"metadata":"{\"foo\":\"bar\"}"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("missing %q in %s", want, raw)
		}
	}
}

func TestNoopSink_AppendDoesNotError(t *testing.T) {
	e := audit.Entry{ID: "x", Action: "y", OccurredAt: time.Now()}
	if err := audit.NoopSink.Append(context.Background(), e); err != nil {
		t.Errorf("NoopSink.Append: %v", err)
	}
}

func TestConstants_NonEmpty(t *testing.T) {
	if audit.Subject == "" || audit.StreamName == "" {
		t.Error("audit wire constants must be non-empty")
	}
	if audit.StreamMaxAge <= 0 {
		t.Error("StreamMaxAge must be positive")
	}
}
