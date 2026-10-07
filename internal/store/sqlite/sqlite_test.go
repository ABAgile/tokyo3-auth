package sqlite

import (
	"testing"

	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/abagile/tokyo3-auth/internal/store/storetest"
)

// Compile-time assertion: *DB satisfies the full store.Store contract.
var _ store.Store = (*DB)(nil)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	// In-memory DB; the modernc.org/sqlite driver supports ":memory:" but we
	// need a single shared connection for it to behave like one DB across
	// queries — Open() already caps MaxOpenConns to 1.
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestMigrationsApply confirms every embedded migration applies on a fresh
// DB and that the schema_migrations tracking table records each one.
func TestMigrationsApply(t *testing.T) {
	db := openTestDB(t)

	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n != 21 {
		t.Errorf("expected 21 migrations applied, got %d", n)
	}

	// Re-running migrate() must be a no-op (idempotent).
	if err := db.migrate(); err != nil {
		t.Fatalf("migrate idempotency: %v", err)
	}
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatalf("count migrations 2: %v", err)
	}
	if n != 21 {
		t.Errorf("after re-run, expected still 21 migrations, got %d", n)
	}
}

// TestStoreContract runs the shared behavioural contract (also run against
// PostgreSQL) on an in-memory SQLite store.
func TestStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return openTestDB(t) })
}
