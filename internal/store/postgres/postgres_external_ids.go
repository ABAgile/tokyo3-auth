package postgres

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

func (s *DB) GetExternalID(ctx context.Context, provider string, userID uuid.UUID) (string, error) {
	var ext string
	err := s.db.QueryRowContext(ctx,
		`SELECT external_user_id FROM external_ids WHERE provider = $1 AND user_id = $2`,
		provider, userID).Scan(&ext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", store.ErrNotFound
	}
	return ext, err
}

func (s *DB) SetExternalID(ctx context.Context, provider string, userID uuid.UUID, externalID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO external_ids (provider, user_id, external_user_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (provider, user_id) DO UPDATE
		SET external_user_id = EXCLUDED.external_user_id,
		    updated_at = now()
	`, provider, userID, externalID)
	return err
}

func (s *DB) DeleteExternalID(ctx context.Context, provider string, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM external_ids WHERE provider = $1 AND user_id = $2`,
		provider, userID)
	return err
}
