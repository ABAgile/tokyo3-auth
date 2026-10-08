package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

const grantCols = `id, user_id, client_id, code_hash, code_challenge, nonce, scopes, redirect_uri, expires_at, used_at, mfa_verified_at, auth_time`

func scanGrant(row interface{ Scan(...any) error }) (*model.Grant, error) {
	g := &model.Grant{}
	var usedAt, mfaAt, authAt sql.NullTime
	err := row.Scan(
		&g.ID, &g.UserID, &g.ClientID, &g.CodeHash, &g.CodeChallenge,
		&g.Nonce, (*stringArray)(&g.Scopes), &g.RedirectURI,
		&g.ExpiresAt, &usedAt, &mfaAt, &authAt,
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
	if mfaAt.Valid {
		t := mfaAt.Time
		g.MFAVerifiedAt = &t
	}
	if authAt.Valid {
		g.AuthTime = authAt.Time
	}
	return g, nil
}

func (s *DB) CreateGrant(ctx context.Context, g *model.Grant) error {
	var authAt any
	if !g.AuthTime.IsZero() {
		authAt = g.AuthTime
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO grants (id, user_id, client_id, code_hash, code_challenge, nonce, scopes, redirect_uri, expires_at, mfa_verified_at, auth_time)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.ID, g.UserID, g.ClientID, g.CodeHash, g.CodeChallenge,
		g.Nonce, stringArray(g.Scopes), g.RedirectURI, g.ExpiresAt, g.MFAVerifiedAt, authAt)
	return err
}

func (s *DB) GetGrantByCodeHash(ctx context.Context, codeHash string) (*model.Grant, error) {
	return scanGrant(s.db.QueryRowContext(ctx, `SELECT `+grantCols+` FROM grants WHERE code_hash = ?`, codeHash))
}

func (s *DB) MarkGrantUsed(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `UPDATE grants SET used_at = CURRENT_TIMESTAMP WHERE id = ? AND used_at IS NULL`, id)
	if err != nil {
		return err
	}
	return requireOneRow(res)
}

// requireOneRow maps a zero-row UPDATE to store.ErrNotFound.
func requireOneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) DeleteExpiredGrants(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE expires_at < CURRENT_TIMESTAMP`)
	return err
}
