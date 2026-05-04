package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

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
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO app_integrations (id, name, provider, enabled, config, encrypted_token, encrypted_dek)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+integrationCols,
		i.ID, i.Name, i.Provider, i.Enabled, configRaw, i.EncryptedToken, i.EncryptedDEK)
	got, err := scanIntegration(row)
	if isUnique(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	*i = *got
	return nil
}

func (s *DB) GetIntegration(ctx context.Context, id uuid.UUID) (*model.AppIntegration, error) {
	return scanIntegration(s.db.QueryRowContext(ctx,
		`SELECT `+integrationCols+` FROM app_integrations WHERE id = $1`, id))
}

func (s *DB) GetIntegrationByName(ctx context.Context, name string) (*model.AppIntegration, error) {
	return scanIntegration(s.db.QueryRowContext(ctx,
		`SELECT `+integrationCols+` FROM app_integrations WHERE name = $1`, name))
}

func (s *DB) ListIntegrations(ctx context.Context) ([]*model.AppIntegration, error) {
	return s.queryIntegrations(ctx,
		`SELECT `+integrationCols+` FROM app_integrations ORDER BY created_at`)
}

func (s *DB) ListEnabledIntegrations(ctx context.Context) ([]*model.AppIntegration, error) {
	return s.queryIntegrations(ctx,
		`SELECT `+integrationCols+` FROM app_integrations WHERE enabled = TRUE ORDER BY created_at`)
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
		   SET name = $2, provider = $3, enabled = $4, config = $5,
		       encrypted_token = $6, encrypted_dek = $7, updated_at = NOW()
		 WHERE id = $1`,
		i.ID, i.Name, i.Provider, i.Enabled, configRaw, i.EncryptedToken, i.EncryptedDEK)
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
	res, err := s.db.ExecContext(ctx, `DELETE FROM app_integrations WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}
