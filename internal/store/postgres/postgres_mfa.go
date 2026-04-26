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

// ── TOTP ──────────────────────────────────────────────────────────────────────

func (s *DB) CreateTOTPCredential(ctx context.Context, c *model.TOTPCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO totp_credentials (id, user_id, encrypted_secret, encrypted_dek, enabled)
		VALUES ($1, $2, $3, $4, $5)`,
		c.ID, c.UserID, c.EncryptedSecret, c.EncryptedDEK, c.Enabled)
	if isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) GetTOTPByUserID(ctx context.Context, userID uuid.UUID) (*model.TOTPCredential, error) {
	c := &model.TOTPCredential{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, encrypted_secret, encrypted_dek, enabled, created_at FROM totp_credentials WHERE user_id = $1`,
		userID).Scan(&c.ID, &c.UserID, &c.EncryptedSecret, &c.EncryptedDEK, &c.Enabled, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (s *DB) EnableTOTP(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `UPDATE totp_credentials SET enabled = TRUE WHERE id = $1`, id)
	return err
}

func (s *DB) DeleteTOTP(ctx context.Context, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM totp_credentials WHERE user_id = $1`, userID)
	return err
}

// ── WebAuthn credentials ──────────────────────────────────────────────────────

func (s *DB) CreateWebAuthnCredential(ctx context.Context, c *model.WebAuthnCredential) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, aaguid, sign_count, device_name)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.AAGUID, c.SignCount, c.DeviceName)
	if isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) ListWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*model.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, credential_id, public_key, aaguid, sign_count, device_name, created_at, last_used_at
		 FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var creds []*model.WebAuthnCredential
	for rows.Next() {
		c := &model.WebAuthnCredential{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AAGUID, &c.SignCount, &c.DeviceName, &c.CreatedAt, &c.LastUsedAt); err != nil {
			return nil, err
		}
		creds = append(creds, c)
	}
	return creds, rows.Err()
}

func (s *DB) GetWebAuthnCredentialByCredentialID(ctx context.Context, credID []byte) (*model.WebAuthnCredential, error) {
	c := &model.WebAuthnCredential{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, credential_id, public_key, aaguid, sign_count, device_name, created_at, last_used_at
		 FROM webauthn_credentials WHERE credential_id = $1`, credID).
		Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AAGUID, &c.SignCount, &c.DeviceName, &c.CreatedAt, &c.LastUsedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (s *DB) UpdateWebAuthnSignCount(ctx context.Context, id uuid.UUID, signCount uint32, lastUsed time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE webauthn_credentials SET sign_count = $2, last_used_at = $3 WHERE id = $1`,
		id, signCount, lastUsed)
	return err
}

func (s *DB) DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2`, id, userID)
	return err
}

// ── WebAuthn sessions ─────────────────────────────────────────────────────────

func (s *DB) CreateWebAuthnSession(ctx context.Context, userID uuid.UUID, data []byte, purpose string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO webauthn_sessions (user_id, session_data, purpose)
		VALUES ($1, $2, $3)
		RETURNING id`, userID, data, purpose).Scan(&id)
	return id, err
}

func (s *DB) GetWebAuthnSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, purpose string) ([]byte, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT session_data FROM webauthn_sessions WHERE id = $1 AND user_id = $2 AND purpose = $3 AND expires_at > NOW()`,
		id, userID, purpose).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return data, err
}

func (s *DB) DeleteWebAuthnSession(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM webauthn_sessions WHERE id = $1`, id)
	return err
}
