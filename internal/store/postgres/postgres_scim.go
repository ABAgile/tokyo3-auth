package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

func (s *DB) CreateSCIMToken(ctx context.Context, t *model.SCIMToken) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO scim_tokens (id, token_hash, description)
		VALUES ($1, $2, $3)`, t.ID, t.TokenHash, t.Description)
	if isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) GetSCIMTokenByHash(ctx context.Context, hash string) (*model.SCIMToken, error) {
	t := &model.SCIMToken{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, token_hash, description, created_at FROM scim_tokens WHERE token_hash = $1`, hash).
		Scan(&t.ID, &t.TokenHash, &t.Description, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return t, err
}

func (s *DB) ListSCIMTokens(ctx context.Context) ([]*model.SCIMToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, token_hash, description, created_at FROM scim_tokens ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tokens []*model.SCIMToken
	for rows.Next() {
		t := &model.SCIMToken{}
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.Description, &t.CreatedAt); err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *DB) DeleteSCIMToken(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM scim_tokens WHERE id = $1`, id)
	return err
}
