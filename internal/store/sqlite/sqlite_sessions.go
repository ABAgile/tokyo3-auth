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

const sessionCols = `id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, expires_at, last_activity_at, mfa_verified, created_at`

func scanSession(row interface{ Scan(...any) error }) (*model.Session, error) {
	sess := &model.Session{}
	err := row.Scan(
		&sess.ID, &sess.UserID, &sess.ClientID, &sess.AccessTokenHash, &sess.RefreshTokenHash,
		(*stringArray)(&sess.Scopes), &sess.ExpiresAt, &sess.LastActivityAt,
		&sess.MFAVerified, &sess.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return sess, err
}

func (s *DB) CreateSession(ctx context.Context, sess *model.Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, expires_at, mfa_verified)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.ClientID, sess.AccessTokenHash, sess.RefreshTokenHash,
		stringArray(sess.Scopes), sess.ExpiresAt, sess.MFAVerified)
	return err
}

func (s *DB) GetSessionByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE access_token_hash = ?`, hash))
}

func (s *DB) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE refresh_token_hash = ?`, hash))
}

func (s *DB) UpdateSessionActivity(ctx context.Context, id uuid.UUID, lastActivity time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_activity_at = ? WHERE id = ?`, lastActivity, id)
	return err
}

func (s *DB) ExtendSessionExpiry(ctx context.Context, id uuid.UUID, newExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET expires_at = ? WHERE id = ?`, newExpiry, id)
	return err
}

func (s *DB) RotateRefreshToken(ctx context.Context, id uuid.UUID, newRefreshHash string, newExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET refresh_token_hash = ?, expires_at = ? WHERE id = ?`,
		newRefreshHash, newExpiry, id)
	return err
}

func (s *DB) DeleteSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

func (s *DB) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

func (s *DB) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP`)
	return err
}
