// Package sqlite implements store.Store using SQLite via modernc.org/sqlite.
// Migrations are embedded and run automatically on Open.
//
// Type translations from the postgres backend:
//
//	UUID         → TEXT (uuid.UUID's Scan/Value handle the round trip)
//	BOOLEAN      → INTEGER (0/1; database/sql converts bool↔int)
//	BYTEA        → BLOB
//	TEXT[]       → TEXT (JSON-encoded; see the stringArray helper)
//	JSONB        → TEXT
//	TIMESTAMPTZ  → DATETIME (modernc.org/sqlite stores time.Time as RFC3339)
//
// Nullable UUID/time columns are scanned via sql.NullString / sql.NullTime
// because google/uuid does not implement Scan for the **uuid.UUID indirection
// that database/sql would need to write a NULL into a *uuid.UUID field.
package sqlite

import (
	"database/sql"
	"database/sql/driver"
	"embed"
	"encoding/json"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations
var migrationsFS embed.FS

// DB wraps sql.DB and implements store.Store.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and runs migrations.
// SQLite is single-writer; one connection avoids locking contention.
func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	// PRAGMAs must run outside any transaction — switching to WAL mode inside
	// a transaction is rejected by SQLite with "cannot change into wal mode
	// from within a transaction".
	if _, err := db.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlite pragmas: %w", err)
	}

	s := &DB{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *DB) Close() error { return s.db.Close() }

func (s *DB) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		version := e.Name()

		var already int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, version).Scan(&already)
		if already > 0 {
			continue
		}

		data, err := migrationsFS.ReadFile("migrations/" + version)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(data)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("exec migration %s: %w", version, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
	}
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

// isUnique reports whether err originated from a UNIQUE constraint violation.
// modernc.org/sqlite formats these as "UNIQUE constraint failed: …".
func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// stringArray is a []string that round-trips through SQLite as a JSON array.
// Postgres uses native TEXT[]; SQLite has no array type, so we encode as JSON
// for transport and decode on Scan. Empty/null values normalise to []string{}
// (never nil) so callers can range without checking.
type stringArray []string

// Value encodes as a JSON array literal, e.g. ["a","b"]. nil and empty slices
// both serialise as `[]` so the column never stores a JSON null.
func (a stringArray) Value() (driver.Value, error) {
	if a == nil {
		return "[]", nil
	}
	b, err := json.Marshal([]string(a))
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// Scan decodes a JSON array literal back to []string. NULL or empty input
// yields an empty (non-nil) slice.
func (a *stringArray) Scan(src any) error {
	if src == nil {
		*a = []string{}
		return nil
	}
	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("stringArray.Scan: unsupported type %T", src)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		*a = []string{}
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return fmt.Errorf("stringArray.Scan: %w", err)
	}
	if out == nil {
		out = []string{}
	}
	*a = out
	return nil
}
