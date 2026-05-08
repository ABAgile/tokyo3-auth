package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/audit"
	_ "modernc.org/sqlite"
)

// DB wraps a *sql.DB connected to an audit SQLite database.
type DB struct {
	db *sql.DB
}

// Open opens (or creates) an audit SQLite database at path. The schema is
// created inline if absent. SQLite enforces single-writer by capping open conns.
func Open(path string) (*DB, error) {
	sqldb, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open audit sqlite: %w", err)
	}
	sqldb.SetMaxOpenConns(1)
	if _, err := sqldb.Exec(`PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;`); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("audit sqlite pragmas: %w", err)
	}
	if err := sqldb.Ping(); err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("ping audit sqlite: %w", err)
	}
	d := &DB{db: sqldb}
	if err := d.ensureSchema(context.Background()); err != nil {
		sqldb.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) ensureSchema(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS audit_logs (
    id          TEXT     PRIMARY KEY,
    user_id     TEXT,
    client_id   TEXT,
    action      TEXT     NOT NULL,
    ip          TEXT     NOT NULL DEFAULT '',
    user_agent  TEXT     NOT NULL DEFAULT '',
    metadata    TEXT     NOT NULL DEFAULT '{}',
    created_at  DATETIME NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_id    ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_client_id  ON audit_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action     ON audit_logs(action);`)
	if err != nil {
		return fmt.Errorf("audit schema: %w", err)
	}
	return nil
}

func (d *DB) UpsertAuditLog(ctx context.Context, e audit.Entry) error {
	metaJSON := e.Metadata
	if metaJSON == "" {
		metaJSON = "{}"
	}
	_, err := d.db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, user_id, client_id, action, ip, user_agent, metadata, created_at)
		 VALUES (?,?,?,?,?,?,?,?) ON CONFLICT (id) DO NOTHING`,
		e.ID,
		nilIfEmpty(e.UserID), nilIfEmpty(e.ClientID),
		e.Action, e.IP, e.UserAgent, metaJSON, e.OccurredAt,
	)
	return err
}

func (d *DB) ListAuditLogs(ctx context.Context, f audit.Filter) ([]*audit.Row, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}

	where := []string{"1=1"}
	args := []any{}

	if f.UserID != "" {
		where = append(where, "user_id = ?")
		args = append(args, f.UserID)
	}
	if f.ClientID != "" {
		where = append(where, "client_id = ?")
		args = append(args, f.ClientID)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	args = append(args, limit)

	q := fmt.Sprintf(
		`SELECT id, user_id, client_id, action, ip, user_agent, metadata, created_at
		 FROM audit_logs WHERE %s ORDER BY created_at DESC LIMIT ?`,
		strings.Join(where, " AND "),
	)
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*audit.Row
	for rows.Next() {
		var (
			r        audit.Row
			userID   sql.NullString
			clientID sql.NullString
		)
		if err := rows.Scan(&r.ID, &userID, &clientID, &r.Action, &r.IP, &r.UserAgent, &r.Metadata, &r.CreatedAt); err != nil {
			return nil, err
		}
		if userID.Valid {
			r.UserID = userID.String
		}
		if clientID.Valid {
			r.ClientID = clientID.String
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (d *DB) Close() error { return d.db.Close() }

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
