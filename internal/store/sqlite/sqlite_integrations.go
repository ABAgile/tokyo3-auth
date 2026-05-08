package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

const integrationCols = `id, name, provider, enabled, config, encrypted_token, encrypted_dek, created_at, updated_at`

func scanIntegration(row interface{ Scan(...any) error }) (*model.AppIntegration, error) {
	i := &model.AppIntegration{}
	var configRaw []byte
	err := row.Scan(
		&i.ID, &i.Name, &i.Provider, &i.Enabled, &configRaw,
		&i.EncryptedToken, &i.EncryptedDEK, &i.CreatedAt, &i.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(configRaw) > 0 {
		if err := json.Unmarshal(configRaw, &i.Config); err != nil {
			return nil, err
		}
	}
	return i, nil
}

func (s *DB) CreateIntegration(ctx context.Context, i *model.AppIntegration) error {
	if i.ID == uuid.Nil {
		i.ID = uuid.New()
	}
	configRaw, err := json.Marshal(i.Config)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	if i.CreatedAt.IsZero() {
		i.CreatedAt = now
	}
	i.UpdatedAt = now
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO app_integrations (id, name, provider, enabled, config, encrypted_token, encrypted_dek, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		i.ID, i.Name, i.Provider, i.Enabled, string(configRaw),
		i.EncryptedToken, i.EncryptedDEK, i.CreatedAt, i.UpdatedAt)
	if isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) GetIntegration(ctx context.Context, id uuid.UUID) (*model.AppIntegration, error) {
	return scanIntegration(s.db.QueryRowContext(ctx,
		`SELECT `+integrationCols+` FROM app_integrations WHERE id = ?`, id))
}

func (s *DB) GetIntegrationByName(ctx context.Context, name string) (*model.AppIntegration, error) {
	return scanIntegration(s.db.QueryRowContext(ctx,
		`SELECT `+integrationCols+` FROM app_integrations WHERE name = ?`, name))
}

func (s *DB) ListIntegrations(ctx context.Context) ([]*model.AppIntegration, error) {
	return s.queryIntegrations(ctx,
		`SELECT `+integrationCols+` FROM app_integrations ORDER BY created_at`)
}

func (s *DB) ListEnabledIntegrations(ctx context.Context) ([]*model.AppIntegration, error) {
	return s.queryIntegrations(ctx,
		`SELECT `+integrationCols+` FROM app_integrations WHERE enabled = 1 ORDER BY created_at`)
}

func (s *DB) queryIntegrations(ctx context.Context, query string, args ...any) ([]*model.AppIntegration, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AppIntegration
	for rows.Next() {
		i, err := scanIntegration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *DB) UpdateIntegration(ctx context.Context, i *model.AppIntegration) error {
	configRaw, err := json.Marshal(i.Config)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE app_integrations
		   SET name = ?, provider = ?, enabled = ?, config = ?,
		       encrypted_token = ?, encrypted_dek = ?, updated_at = CURRENT_TIMESTAMP
		 WHERE id = ?`,
		i.Name, i.Provider, i.Enabled, string(configRaw),
		i.EncryptedToken, i.EncryptedDEK, i.ID)
	if isUnique(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) DeleteIntegration(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM app_integrations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}
