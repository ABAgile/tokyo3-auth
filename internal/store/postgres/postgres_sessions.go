package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

const sessionCols = `id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, access_expires_at, refresh_expires_at, last_activity_at, mfa_verified, created_at`

func scanSession(row interface{ Scan(...any) error }) (*model.Session, error) {
	s := &model.Session{}
	var nullUser sql.Null[uuid.UUID]
	err := row.Scan(
		&s.ID, &nullUser, &s.ClientID, &s.AccessTokenHash, &s.RefreshTokenHash,
		(*stringArray)(&s.Scopes), &s.AccessExpiresAt, &s.RefreshExpiresAt, &s.LastActivityAt,
		&s.MFAVerified, &s.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if nullUser.Valid {
		s.UserID = nullUser.V
	}
	return s, err
}

func (s *DB) CreateSession(ctx context.Context, sess *model.Session) error {
	// user_id is nullable: machine-credential sessions (client_credentials
	// grant) carry no user. Write NULL instead of the zero UUID so the FK
	// to users(id) is satisfied.
	var userArg any = sess.UserID
	if sess.UserID == uuid.Nil {
		userArg = nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, access_expires_at, refresh_expires_at, mfa_verified)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		sess.ID, userArg, sess.ClientID, sess.AccessTokenHash, sess.RefreshTokenHash,
		stringArray(sess.Scopes), sess.AccessExpiresAt, sess.RefreshExpiresAt, sess.MFAVerified)
	return err
}

func (s *DB) GetSessionByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE access_token_hash = $1`, hash))
}

func (s *DB) GetSessionByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE refresh_token_hash = $1`, hash))
}

func (s *DB) UpdateSessionActivity(ctx context.Context, id uuid.UUID, lastActivity time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_activity_at = $2 WHERE id = $1`, id, lastActivity)
	return err
}

func (s *DB) ExtendSessionExpiry(ctx context.Context, id uuid.UUID, newExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET access_expires_at = $2 WHERE id = $1`, id, newExpiry)
	return err
}

func (s *DB) RotateRefreshToken(ctx context.Context, id uuid.UUID, newRefreshHash string, newAccessExpiry, newRefreshExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET refresh_token_hash = $2, access_expires_at = $3, refresh_expires_at = $4 WHERE id = $1`,
		id, newRefreshHash, newAccessExpiry, newRefreshExpiry)
	return err
}

func (s *DB) DeleteSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	return err
}

func (s *DB) DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

func (s *DB) ListSessionClientIDsByUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT client_id FROM sessions WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *DB) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE refresh_expires_at < NOW()`)
	return err
}
