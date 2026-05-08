package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/abagile/tokyo3-auth/internal/audit"
)

func openTestAuditDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestAuditDB_Open tests Open with an in-memory database.
func TestAuditDB_Open(t *testing.T) {
	db := openTestAuditDB(t)
	if db == nil {
		t.Fatal("expected non-nil DB")
	}
}

// TestAuditDB_UpsertAndList tests UpsertAuditLog and ListAuditLogs.
func TestAuditDB_UpsertAndList(t *testing.T) {
	db := openTestAuditDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const userA = "11111111-1111-1111-1111-111111111111"
	const userB = "22222222-2222-2222-2222-222222222222"
	const clientA = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"

	entries := []audit.Entry{
		{ID: "evt-1", Action: "auth.login", UserID: userA, ClientID: clientA, IP: "127.0.0.1", OccurredAt: now},
		{ID: "evt-2", Action: "auth.logout", UserID: userA, OccurredAt: now.Add(-time.Minute)},
		{ID: "evt-3", Action: "auth.login", UserID: userB, ClientID: clientA, OccurredAt: now.Add(-2 * time.Minute)},
	}

	for _, e := range entries {
		if err := db.UpsertAuditLog(ctx, e); err != nil {
			t.Fatalf("UpsertAuditLog(%q): %v", e.ID, err)
		}
	}

	// Idempotent — re-insert same entries should not error.
	for _, e := range entries {
		if err := db.UpsertAuditLog(ctx, e); err != nil {
			t.Fatalf("UpsertAuditLog duplicate (%q): %v", e.ID, err)
		}
	}

	// No filter — returns all (up to default 50).
	all, err := db.ListAuditLogs(ctx, audit.Filter{})
	if err != nil {
		t.Fatalf("ListAuditLogs no filter: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("expected 3, got %d", len(all))
	}

	// User filter.
	byUser, err := db.ListAuditLogs(ctx, audit.Filter{UserID: userA})
	if err != nil {
		t.Fatalf("ListAuditLogs user filter: %v", err)
	}
	if len(byUser) != 2 {
		t.Errorf("user filter: expected 2, got %d", len(byUser))
	}

	// Client filter.
	byClient, err := db.ListAuditLogs(ctx, audit.Filter{ClientID: clientA})
	if err != nil {
		t.Fatalf("ListAuditLogs client filter: %v", err)
	}
	if len(byClient) != 2 {
		t.Errorf("client filter: expected 2, got %d", len(byClient))
	}

	// Action filter.
	byAction, err := db.ListAuditLogs(ctx, audit.Filter{Action: "auth.login"})
	if err != nil {
		t.Fatalf("ListAuditLogs action filter: %v", err)
	}
	if len(byAction) != 2 {
		t.Errorf("action filter: expected 2, got %d", len(byAction))
	}

	// Limit.
	limited, err := db.ListAuditLogs(ctx, audit.Filter{Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditLogs limit: %v", err)
	}
	if len(limited) != 1 {
		t.Errorf("limit 1: expected 1, got %d", len(limited))
	}

	// Default metadata fill — entries inserted without Metadata still produce
	// a JSON object on ListAuditLogs.
	if all[0].Metadata == "" {
		t.Errorf("expected non-empty default metadata, got empty string")
	}
}

// TestAuditDB_Close tests that Close on an open DB returns nil.
func TestAuditDB_Close(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
