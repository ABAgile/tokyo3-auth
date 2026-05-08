package audit

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestNoopSink_Log tests that NoopSink.Log always returns nil.
func TestNoopSink_Log(t *testing.T) {
	s := NoopSink{}
	err := s.Log(context.Background(), Entry{ID: "e1", Action: "test.action", OccurredAt: time.Now()})
	if err != nil {
		t.Errorf("Log returned non-nil error: %v", err)
	}
}

// TestNoopSink_Close tests that NoopSink.Close always returns nil.
func TestNoopSink_Close(t *testing.T) {
	s := NoopSink{}
	if err := s.Close(); err != nil {
		t.Errorf("Close returned non-nil error: %v", err)
	}
}

// TestEntry_JSONMarshal tests that Entry marshals with correct omitempty behavior.
func TestEntry_JSONMarshal(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	// Full entry.
	full := Entry{
		ID:         "e-1",
		Action:     "auth.login",
		UserID:     "11111111-1111-1111-1111-111111111111",
		ClientID:   "22222222-2222-2222-2222-222222222222",
		IP:         "127.0.0.1",
		UserAgent:  "Mozilla/5.0",
		Metadata:   `{"key":"val"}`,
		OccurredAt: now,
	}

	data, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("Marshal full: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"id", "action", "user_id", "client_id", "ip", "user_agent", "metadata", "occurred_at"} {
		if _, ok := m[field]; !ok {
			t.Errorf("expected field %q in JSON", field)
		}
	}

	// Minimal entry — optional fields should be omitted.
	minimal := Entry{
		ID:         "e-2",
		Action:     "auth.login.failed",
		OccurredAt: now,
	}
	data, err = json.Marshal(minimal)
	if err != nil {
		t.Fatalf("Marshal minimal: %v", err)
	}
	var m2 map[string]any
	if err := json.Unmarshal(data, &m2); err != nil {
		t.Fatal(err)
	}
	for _, omitted := range []string{"user_id", "client_id", "ip", "user_agent", "metadata"} {
		if _, ok := m2[omitted]; ok {
			t.Errorf("field %q should be omitted from minimal entry JSON", omitted)
		}
	}
}

// TestStreamMaxAge_PCIDSSFloor verifies the retention floor remains compliant
// with PCI-DSS 10.5 (12 months minimum retention for audit logs).
func TestStreamMaxAge_PCIDSSFloor(t *testing.T) {
	const oneYear = 365 * 24 * time.Hour
	if StreamMaxAge < oneYear {
		t.Errorf("StreamMaxAge %v is less than PCI-DSS 10.5 floor of %v", StreamMaxAge, oneYear)
	}
}

// TestFilter_ZeroValue ensures the zero Filter is a "list everything, default
// limit" — that's the contract the consumer's query CLI relies on.
func TestFilter_ZeroValue(t *testing.T) {
	var f Filter
	if f.UserID != "" || f.ClientID != "" || f.Action != "" || f.Limit != 0 {
		t.Errorf("zero Filter should be all-empty, got %+v", f)
	}
}
