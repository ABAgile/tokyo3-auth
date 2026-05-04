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

const userCols = `id, email, password_hash, name, active, scim_external_id, mfa_enabled, is_admin,
	password_changed_at, failed_attempts, locked_until, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	u := &model.User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Active,
		&u.SCIMExternalID, &u.MFAEnabled, &u.IsAdmin, &u.PasswordChangedAt,
		&u.FailedAttempts, &u.LockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return u, err
}

func (s *DB) CreateUser(ctx context.Context, email, passwordHash, name string) (*model.User, error) {
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (email, password_hash, name)
		VALUES ($1, $2, $3)
		RETURNING `+userCols, email, passwordHash, name)
	u, err := scanUser(row)
	if isUnique(err) {
		return nil, store.ErrConflict
	}
	return u, err
}

func (s *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = $1`, id))
}

func (s *DB) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = $1`, email))
}

func (s *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *DB) ListUsers(ctx context.Context) ([]*model.User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *DB) UpdateUser(ctx context.Context, id uuid.UUID, name string, active bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET name = $2, active = $3, updated_at = NOW() WHERE id = $1`,
		id, name, active)
	return err
}

func (s *DB) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = $2, password_changed_at = NOW(), updated_at = NOW() WHERE id = $1`,
		id, passwordHash)
	return err
}

func (s *DB) UpdateUserMFAEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET mfa_enabled = $2, updated_at = NOW() WHERE id = $1`,
		id, enabled)
	return err
}

func (s *DB) UpdateUserFailedAttempts(ctx context.Context, id uuid.UUID, count int, lockedUntil *time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET failed_attempts = $2, locked_until = $3, updated_at = NOW() WHERE id = $1`,
		id, count, lockedUntil)
	return err
}

func (s *DB) SetUserActive(ctx context.Context, id uuid.UUID, active bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET active = $2, updated_at = NOW() WHERE id = $1`,
		id, active)
	return err
}

func (s *DB) SetUserSCIMExternalID(ctx context.Context, id uuid.UUID, externalID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET scim_external_id = $2, updated_at = NOW() WHERE id = $1`,
		id, externalID)
	return err
}

func (s *DB) SetUserAdmin(ctx context.Context, id uuid.UUID, isAdmin bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET is_admin = $2, updated_at = NOW() WHERE id = $1`,
		id, isAdmin)
	return err
}

func (s *DB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}
