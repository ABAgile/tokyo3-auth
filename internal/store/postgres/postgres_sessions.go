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

const sessionCols = `id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, access_expires_at, refresh_expires_at, last_activity_at, mfa_verified, mfa_verified_at, auth_time, created_at`

func scanSession(row interface{ Scan(...any) error }) (*model.Session, error) {
	s := &model.Session{}
	var nullUser sql.Null[uuid.UUID]
	var mfaAt, authAt sql.NullTime
	err := row.Scan(
		&s.ID, &nullUser, &s.ClientID, &s.AccessTokenHash, &s.RefreshTokenHash,
		(*stringArray)(&s.Scopes), &s.AccessExpiresAt, &s.RefreshExpiresAt, &s.LastActivityAt,
		&s.MFAVerified, &mfaAt, &authAt, &s.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if nullUser.Valid {
		s.UserID = nullUser.V
	}
	if mfaAt.Valid {
		t := mfaAt.Time
		s.MFAVerifiedAt = &t
	}
	if authAt.Valid {
		s.AuthTime = authAt.Time
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
	var mfaAt any
	if sess.MFAVerifiedAt != nil {
		mfaAt = *sess.MFAVerifiedAt
	}
	var authAt any
	if !sess.AuthTime.IsZero() {
		authAt = sess.AuthTime
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, client_id, access_token_hash, refresh_token_hash, scopes, access_expires_at, refresh_expires_at, mfa_verified, mfa_verified_at, auth_time)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		sess.ID, userArg, sess.ClientID, sess.AccessTokenHash, sess.RefreshTokenHash,
		stringArray(sess.Scopes), sess.AccessExpiresAt, sess.RefreshExpiresAt, sess.MFAVerified, mfaAt, authAt)
	return err
}

// MarkSessionMFA updates the MFA freshness columns on an existing
// session. Called after a step-up MFA challenge succeeds so the next
// step-up gate sees a fresh timestamp without minting a new session
// row.
func (s *DB) MarkSessionMFA(ctx context.Context, id uuid.UUID, when time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET mfa_verified = TRUE, mfa_verified_at = $2 WHERE id = $1`, id, when)
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

func (s *DB) RotateRefreshToken(ctx context.Context, id uuid.UUID, oldRefreshHash, newAccessHash, newRefreshHash string, newAccessExpiry, newRefreshExpiry time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx,
		`UPDATE sessions SET access_token_hash = $3, refresh_token_hash = $4, access_expires_at = $5, refresh_expires_at = $6
		 WHERE id = $1 AND refresh_token_hash = $2`,
		id, oldRefreshHash, newAccessHash, newRefreshHash, newAccessExpiry, newRefreshExpiry)
	if err != nil {
		return err
	}
	if err := requireOneRow(res); err != nil {
		return err
	}
	// Remember the retired token so a later replay is recognisable.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO retired_refresh_tokens (token_hash, session_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		oldRefreshHash, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *DB) GetSessionByRetiredRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error) {
	return scanSession(s.db.QueryRowContext(ctx,
		`SELECT `+sessionCols+` FROM sessions WHERE id = (SELECT session_id FROM retired_refresh_tokens WHERE token_hash = $1)`, hash))
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
