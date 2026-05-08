package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

func (s *DB) CreateSigningKey(ctx context.Context, k *model.SigningKey) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO signing_keys (id, encrypted_private_key, encrypted_dek, algorithm, kid, active)
		VALUES (?, ?, ?, ?, ?, ?)`,
		k.ID, k.EncryptedPrivateKey, k.EncryptedDEK, k.Algorithm, k.KID, k.Active)
	return err
}

func (s *DB) GetActiveSigningKey(ctx context.Context) (*model.SigningKey, error) {
	k := &model.SigningKey{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, encrypted_private_key, encrypted_dek, algorithm, kid, active, created_at
		 FROM signing_keys WHERE active = 1 ORDER BY created_at DESC LIMIT 1`).
		Scan(&k.ID, &k.EncryptedPrivateKey, &k.EncryptedDEK, &k.Algorithm, &k.KID, &k.Active, &k.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return k, err
}

func (s *DB) ListActiveSigningKeys(ctx context.Context) ([]*model.SigningKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, encrypted_private_key, encrypted_dek, algorithm, kid, active, created_at
		 FROM signing_keys WHERE active = 1 ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*model.SigningKey
	for rows.Next() {
		k := &model.SigningKey{}
		if err := rows.Scan(&k.ID, &k.EncryptedPrivateKey, &k.EncryptedDEK, &k.Algorithm, &k.KID, &k.Active, &k.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *DB) DeactivateSigningKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `UPDATE signing_keys SET active = 0 WHERE id = ?`, id)
	return err
}
