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

const clientCols = `id, client_id, client_secret_hash, name, redirect_uris, scopes, public, backchannel_logout_uri, secret_rotated_at, created_at`

func scanClient(row interface{ Scan(...any) error }) (*model.Client, error) {
	c := &model.Client{}
	err := row.Scan(
		&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name,
		(*stringArray)(&c.RedirectURIs),
		(*stringArray)(&c.Scopes),
		&c.Public, &c.BackchannelLogoutURI, &c.SecretRotatedAt, &c.CreatedAt,
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
