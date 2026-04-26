package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

const clientCols = `id, client_id, client_secret_hash, name, redirect_uris, scopes, public, secret_rotated_at, created_at`

func scanClient(row interface{ Scan(...any) error }) (*model.Client, error) {
	c := &model.Client{}
	err := row.Scan(
		&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name,
		(*stringArray)(&c.RedirectURIs),
		(*stringArray)(&c.Scopes),
		&c.Public, &c.SecretRotatedAt, &c.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (s *DB) CreateClient(ctx context.Context, clientID, clientSecretHash, name string, redirectURIs, scopes []string, public bool) (*model.Client, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO clients (client_id, client_secret_hash, name, redirect_uris, scopes, public)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+clientCols,
		clientID, clientSecretHash, name,
		stringArray(redirectURIs), stringArray(scopes), public)
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
