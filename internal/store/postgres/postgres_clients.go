package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

const clientCols = `id, client_id, client_secret_hash, name, redirect_uris, scopes, public, backchannel_logout_uri, show_in_portal, launch_url, brand_color, icon_url, visible_to_all, secret_rotated_at, created_at`

func scanClient(row interface{ Scan(...any) error }) (*model.Client, error) {
	c := &model.Client{}
	err := row.Scan(
		&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name,
		(*stringArray)(&c.RedirectURIs),
		(*stringArray)(&c.Scopes),
		&c.Public, &c.BackchannelLogoutURI,
		&c.ShowInPortal, &c.LaunchURL, &c.BrandColor, &c.IconURL, &c.VisibleToAll,
		&c.SecretRotatedAt, &c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (s *DB) CreateClient(ctx context.Context, clientID, clientSecretHash, name string, redirectURIs, scopes []string, public bool, backchannelLogoutURI *string) (*model.Client, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO clients (client_id, client_secret_hash, name, redirect_uris, scopes, public, backchannel_logout_uri)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+clientCols,
		clientID, clientSecretHash, name,
		stringArray(redirectURIs), stringArray(scopes), public, backchannelLogoutURI)
	c, err := scanClient(row)
	if isUnique(err) {
		return nil, store.ErrConflict
	}
	return c, err
}

func (s *DB) GetClientByID(ctx context.Context, id uuid.UUID) (*model.Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE id = $1`, id))
}

func (s *DB) GetClientByClientID(ctx context.Context, clientID string) (*model.Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE client_id = $1`, clientID))
}

func (s *DB) ListClients(ctx context.Context) ([]*model.Client, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+clientCols+` FROM clients ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []*model.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	return clients, rows.Err()
}

func (s *DB) UpdateClient(ctx context.Context, id uuid.UUID, name string, redirectURIs, scopes []string, public bool, backchannelLogoutURI *string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE clients SET name = $2, redirect_uris = $3, scopes = $4, public = $5, backchannel_logout_uri = $6 WHERE id = $1`,
		id, name, stringArray(redirectURIs), stringArray(scopes), public, backchannelLogoutURI)
	return err
}

func (s *DB) UpdateClientSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE clients SET client_secret_hash = $2, secret_rotated_at = NOW() WHERE id = $1`,
		id, secretHash)
	return err
}

func (s *DB) DeleteClient(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = $1`, id)
	return err
}

func (s *DB) UpdateClientPortalConfig(ctx context.Context, id uuid.UUID, showInPortal bool, launchURL, brandColor, iconURL string, visibleToAll bool) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE clients
		   SET show_in_portal = $2, launch_url = $3, brand_color = $4, icon_url = $5, visible_to_all = $6
		 WHERE id = $1`,
		id, showInPortal, launchURL, brandColor, iconURL, visibleToAll)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ReplaceClientVisibility uses a transactional delete-then-insert pattern
// for parity with ReplaceGroupMembers. Per-row idempotency on the
// (client_id, group_id) unique constraint prevents accidental duplicates
// when a concurrent edit races us.
func (s *DB) ReplaceClientVisibility(ctx context.Context, clientID uuid.UUID, groupIDs []uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM client_visibility WHERE client_id = $1`, clientID); err != nil {
		return err
	}
	for _, gid := range groupIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO client_visibility (client_id, group_id) VALUES ($1, $2)
			 ON CONFLICT (client_id, group_id) DO NOTHING`,
			clientID, gid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *DB) ListClientVisibility(ctx context.Context, clientID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_id FROM client_visibility WHERE client_id = $1 ORDER BY created_at`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var gid uuid.UUID
		if err := rows.Scan(&gid); err != nil {
			return nil, err
		}
		out = append(out, gid)
	}
	return out, rows.Err()
}

// ListPortalClientsForUser joins clients ← client_visibility ←
// scim_group_members for one user, plus the visible_to_all shortcut.
// DISTINCT collapses duplicates when a user belongs to multiple linked
// groups for the same client. Sentinel/system clients are excluded by
// the show_in_portal=false default and stay invisible unless explicitly
// opted in.
func (s *DB) ListPortalClientsForUser(ctx context.Context, userID uuid.UUID) ([]*model.Client, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT `+prefixCols("c", clientCols)+`
		  FROM clients c
		  LEFT JOIN client_visibility v   ON v.client_id = c.id
		  LEFT JOIN scim_group_members m  ON m.group_id  = v.group_id AND m.user_id = $1
		 WHERE c.show_in_portal = TRUE
		   AND (c.visible_to_all = TRUE OR m.user_id = $1)
		 ORDER BY c.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// prefixCols rewrites a comma-separated column list "a, b, c" as
// "p.a, p.b, p.c" so we can reuse clientCols inside a JOIN where the
// columns must be qualified.
func prefixCols(prefix, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = prefix + "." + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}
