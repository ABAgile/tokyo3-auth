package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

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
	now := time.Now().UTC()
	c := &model.Client{
		ID:                   uuid.New(),
		ClientID:             clientID,
		ClientSecretHash:     clientSecretHash,
		Name:                 name,
		RedirectURIs:         redirectURIs,
		Scopes:               scopes,
		Public:               public,
		BackchannelLogoutURI: backchannelLogoutURI,
		SecretRotatedAt:      now,
		CreatedAt:            now,
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO clients (id, client_id, client_secret_hash, name, redirect_uris, scopes, public, backchannel_logout_uri, secret_rotated_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.ClientID, c.ClientSecretHash, c.Name,
		stringArray(c.RedirectURIs), stringArray(c.Scopes),
		c.Public, c.BackchannelLogoutURI, c.SecretRotatedAt, c.CreatedAt)
	if isUnique(err) {
		return nil, store.ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *DB) GetClientByID(ctx context.Context, id uuid.UUID) (*model.Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE id = ?`, id))
}

func (s *DB) GetClientByClientID(ctx context.Context, clientID string) (*model.Client, error) {
	return scanClient(s.db.QueryRowContext(ctx, `SELECT `+clientCols+` FROM clients WHERE client_id = ?`, clientID))
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
		`UPDATE clients SET name = ?, redirect_uris = ?, scopes = ?, public = ?, backchannel_logout_uri = ? WHERE id = ?`,
		name, stringArray(redirectURIs), stringArray(scopes), public, backchannelLogoutURI, id)
	return err
}

func (s *DB) UpdateClientSecret(ctx context.Context, id uuid.UUID, secretHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE clients SET client_secret_hash = ?, secret_rotated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		secretHash, id)
	return err
}

func (s *DB) DeleteClient(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM clients WHERE id = ?`, id)
	return err
}

func (s *DB) UpdateClientPortalConfig(ctx context.Context, id uuid.UUID, showInPortal bool, launchURL, brandColor, iconURL string, visibleToAll bool) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE clients
		   SET show_in_portal = ?, launch_url = ?, brand_color = ?, icon_url = ?, visible_to_all = ?
		 WHERE id = ?`,
		showInPortal, launchURL, brandColor, iconURL, visibleToAll, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) ReplaceClientVisibility(ctx context.Context, clientID uuid.UUID, groupIDs []uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM client_visibility WHERE client_id = ?`, clientID); err != nil {
		return err
	}
	for _, gid := range groupIDs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO client_visibility (id, client_id, group_id, created_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP)
			ON CONFLICT (client_id, group_id) DO NOTHING`,
			uuid.New(), clientID, gid); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *DB) ListClientVisibility(ctx context.Context, clientID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT group_id FROM client_visibility WHERE client_id = ? ORDER BY created_at`, clientID)
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

// ListPortalClientsForUser: see postgres equivalent for design notes.
// SQLite needs `c.` prefixes hand-written rather than the prefixCols
// helper used in postgres, because the column list interpolation
// happens at compile time of the SQL string and SQLite's parser is
// stricter about it. Kept the column list inline for readability.
func (s *DB) ListPortalClientsForUser(ctx context.Context, userID uuid.UUID) ([]*model.Client, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT
		    c.id, c.client_id, c.client_secret_hash, c.name,
		    c.redirect_uris, c.scopes, c.public, c.backchannel_logout_uri,
		    c.show_in_portal, c.launch_url, c.brand_color, c.icon_url, c.visible_to_all,
		    c.secret_rotated_at, c.created_at
		  FROM clients c
		  LEFT JOIN client_visibility v   ON v.client_id = c.id
		  LEFT JOIN scim_group_members m  ON m.group_id  = v.group_id AND m.user_id = ?
		 WHERE c.show_in_portal = 1
		   AND (c.visible_to_all = 1 OR m.user_id = ?)
		 ORDER BY c.name`, userID, userID)
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
