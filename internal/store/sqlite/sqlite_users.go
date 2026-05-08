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

const userCols = `id, email, password_hash, name, active, scim_external_id, mfa_enabled, is_admin,
	password_changed_at, failed_attempts, locked_until, created_at, updated_at`

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	u := &model.User{}
	var lockedUntil sql.NullTime
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Active,
		&u.SCIMExternalID, &u.MFAEnabled, &u.IsAdmin, &u.PasswordChangedAt,
		&u.FailedAttempts, &lockedUntil, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lockedUntil.Valid {
		t := lockedUntil.Time
		u.LockedUntil = &t
	}
	return u, nil
}

func (s *DB) CreateUser(ctx context.Context, email, passwordHash, name string) (*model.User, error) {
	now := time.Now().UTC()
	u := &model.User{
		ID:                uuid.New(),
		Email:             email,
		PasswordHash:      passwordHash,
		Name:              name,
		Active:            true,
		PasswordChangedAt: now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, email, password_hash, name, active, password_changed_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, 1, ?, ?, ?)`,
		u.ID, u.Email, u.PasswordHash, u.Name, u.PasswordChangedAt, u.CreatedAt, u.UpdatedAt)
	if isUnique(err) {
		return nil, store.ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

func (s *DB) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE email = ?`, email))
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
		`UPDATE users SET name = ?, active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		name, active, id)
	return err
}

func (s *DB) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		passwordHash, id)
	return err
}

func (s *DB) UpdateUserMFAEnabled(ctx context.Context, id uuid.UUID, enabled bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET mfa_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		enabled, id)
	return err
}

func (s *DB) UpdateUserFailedAttempts(ctx context.Context, id uuid.UUID, count int, lockedUntil *time.Time) error {
	var locked any
	if lockedUntil != nil {
		locked = *lockedUntil
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		count, locked, id)
	return err
}

func (s *DB) SetUserActive(ctx context.Context, id uuid.UUID, active bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		active, id)
	return err
}

func (s *DB) SetUserSCIMExternalID(ctx context.Context, id uuid.UUID, externalID string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET scim_external_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		externalID, id)
	return err
}

func (s *DB) SetUserAdmin(ctx context.Context, id uuid.UUID, isAdmin bool) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET is_admin = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
		isAdmin, id)
	return err
}

func (s *DB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	return err
}
