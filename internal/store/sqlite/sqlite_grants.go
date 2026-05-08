package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

const grantCols = `id, user_id, client_id, code_hash, code_challenge, nonce, scopes, redirect_uri, expires_at, used_at`

func scanGrant(row interface{ Scan(...any) error }) (*model.Grant, error) {
	g := &model.Grant{}
	var usedAt sql.NullTime
	err := row.Scan(
		&g.ID, &g.UserID, &g.ClientID, &g.CodeHash, &g.CodeChallenge,
		&g.Nonce, (*stringArray)(&g.Scopes), &g.RedirectURI,
		&g.ExpiresAt, &usedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if usedAt.Valid {
		t := usedAt.Time
		g.UsedAt = &t
	}
	return g, nil
}

func (s *DB) CreateGrant(ctx context.Context, g *model.Grant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO grants (id, user_id, client_id, code_hash, code_challenge, nonce, scopes, redirect_uri, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.UserID, g.ClientID, g.CodeHash, g.CodeChallenge,
		g.Nonce, stringArray(g.Scopes), g.RedirectURI, g.ExpiresAt)
	return err
}

func (s *DB) GetGrantByCodeHash(ctx context.Context, codeHash string) (*model.Grant, error) {
	return scanGrant(s.db.QueryRowContext(ctx, `SELECT `+grantCols+` FROM grants WHERE code_hash = ?`, codeHash))
}

func (s *DB) MarkGrantUsed(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `UPDATE grants SET used_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

func (s *DB) DeleteExpiredGrants(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE expires_at < CURRENT_TIMESTAMP`)
	return err
}
