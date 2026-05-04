// Package postgres implements store.Store using PostgreSQL via pgx/v5.
package postgres

import (
	"crypto/tls"
	"database/sql"
	"database/sql/driver"
	"embed"
	"errors"
	"fmt"
	"strings"
	"time"

	pgx "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	pgxstdlib "github.com/jackc/pgx/v5/stdlib"

	// Register the "pgx" sql driver used by Migrate.
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations
var migrationsFS embed.FS

// DB wraps sql.DB and implements store.Store for PostgreSQL.
type DB struct {
	db *sql.DB
}

// Migrate connects with the admin DSN and runs all pending schema migrations.
// Call once at startup before opening the runtime connection via Open. tlsCfg
// may be nil; when non-nil it enables client certificate auth (mTLS).
func Migrate(dsn string, tlsCfg *tls.Config) error {
	db, err := openWithTLS(dsn, tlsCfg)
	if err != nil {
		return fmt.Errorf("open admin postgres: %w", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping admin postgres: %w", err)
	}
	return (&DB{db: db}).migrate()
}

// OpenWithTLS connects using a custom TLS config, enabling client certificate
// authentication when tlsCfg is non-nil. Pass nil for a plain (DSN-only) connection.
// Call Migrate first.
func OpenWithTLS(dsn string, tlsCfg *tls.Config) (*DB, error) {
	db, err := openWithTLS(dsn, tlsCfg)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &DB{db: db}, nil
}

func openWithTLS(dsn string, tlsCfg *tls.Config) (*sql.DB, error) {
	connCfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	if tlsCfg != nil {
		if tlsCfg.ServerName == "" {
			tlsCfg.ServerName = connCfg.Host
		}
		connCfg.TLSConfig = tlsCfg
	}
	return pgxstdlib.OpenDB(*connCfg), nil
}

func (s *DB) Close() error { return s.db.Close() }

func (s *DB) migrate() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = $1`, version).Scan(&already)
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
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", version, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", version, err)
		}
	}
	return nil
}

func isUnique(err error) bool {
	if err == nil {
		return false
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code == "23505"
	}
	return false
}

// ── stringArray: database/sql-compatible PostgreSQL TEXT[] type ───────────────

// stringArray is a []string that encodes to/from the PostgreSQL TEXT[] wire format.
type stringArray []string

// Value encodes as a PostgreSQL array literal: {"a","b",...}
func (a stringArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, s := range a {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteByte('"')
		// Escape backslash and double-quote inside quoted element.
		for _, c := range s {
			if c == '\\' || c == '"' {
				b.WriteByte('\\')
			}
			b.WriteRune(c)
		}
		b.WriteByte('"')
	}
	b.WriteByte('}')
	return b.String(), nil
}

// Scan decodes from a PostgreSQL array literal.
func (a *stringArray) Scan(src any) error {
	if src == nil {
		*a = nil
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
	parsed, err := parsePostgresTextArray(s)
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// parsePostgresTextArray parses a PostgreSQL TEXT[] literal like {a,b} or {"a b","c"}.
func parsePostgresTextArray(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if s == "{}" {
		return []string{}, nil
	}
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return nil, fmt.Errorf("invalid postgres array: %q", s)
	}
	inner := s[1 : len(s)-1]
	if inner == "" {
		return []string{}, nil
	}
	var result []string
	var cur strings.Builder
	quoted := false
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if quoted {
			if c == '\\' && i+1 < len(inner) {
				i++
				cur.WriteByte(inner[i])
			} else if c == '"' {
				quoted = false
			} else {
				cur.WriteByte(c)
			}
		} else if c == '"' {
			quoted = true
		} else if c == ',' {
			result = append(result, cur.String())
			cur.Reset()
		} else {
			cur.WriteByte(c)
		}
	}
	result = append(result, cur.String())
	return result, nil
}
