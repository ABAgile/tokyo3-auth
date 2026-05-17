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

const sessionCols = `id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, access_expires_at, refresh_expires_at, last_activity_at, mfa_verified, created_at`

func scanSession(row interface{ Scan(...any) error }) (*model.Session, error) {
	sess := &model.Session{}
	var nullUser sql.Null[uuid.UUID]
	err := row.Scan(
		&sess.ID, &nullUser, &sess.ClientID, &sess.AccessTokenHash, &sess.RefreshTokenHash,
		(*stringArray)(&sess.Scopes), &sess.AccessExpiresAt, &sess.RefreshExpiresAt, &sess.LastActivityAt,
		&sess.MFAVerified, &sess.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if nullUser.Valid {
		sess.UserID = nullUser.V
	}
	return sess, err
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, userArg, sess.ClientID, sess.AccessTokenHash, sess.RefreshTokenHash,
		stringArray(sess.Scopes), sess.AccessExpiresAt, sess.RefreshExpiresAt, sess.MFAVerified)
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
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET access_expires_at = ? WHERE id = ?`, newExpiry, id)
	return err
}

func (s *DB) RotateRefreshToken(ctx context.Context, id uuid.UUID, newRefreshHash string, newAccessExpiry, newRefreshExpiry time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET refresh_token_hash = ?, access_expires_at = ?, refresh_expires_at = ? WHERE id = ?`,
		newRefreshHash, newAccessExpiry, newRefreshExpiry, id)
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

func (s *DB) ListSessionClientIDsByUser(ctx context.Context, userID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT client_id FROM sessions WHERE user_id = ?`, userID)
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
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE refresh_expires_at < CURRENT_TIMESTAMP`)
	return err
}
