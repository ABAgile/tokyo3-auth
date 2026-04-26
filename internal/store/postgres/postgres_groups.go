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

func (s *DB) CreateGroup(ctx context.Context, displayName string) (*model.SCIMGroup, error) {
	id := uuid.New()
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scim_groups (id, display_name) VALUES ($1, $2)`, id, displayName)
	if err != nil {
		return nil, err
	}
	return &model.SCIMGroup{ID: id, DisplayName: displayName, CreatedAt: now, UpdatedAt: now}, nil
}

func (s *DB) GetGroupByID(ctx context.Context, id uuid.UUID) (*model.SCIMGroup, error) {
	g := &model.SCIMGroup{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, display_name, created_at, updated_at FROM scim_groups WHERE id = $1`, id).
		Scan(&g.ID, &g.DisplayName, &g.CreatedAt, &g.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	g.Members, _ = s.groupMembers(ctx, id)
	return g, nil
}

func (s *DB) ListGroups(ctx context.Context) ([]*model.SCIMGroup, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, display_name, created_at, updated_at FROM scim_groups ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var groups []*model.SCIMGroup
	for rows.Next() {
		g := &model.SCIMGroup{}
		if err := rows.Scan(&g.ID, &g.DisplayName, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		g.Members, _ = s.groupMembers(ctx, g.ID)
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

func (s *DB) UpdateGroup(ctx context.Context, id uuid.UUID, displayName string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scim_groups SET display_name = $2, updated_at = NOW() WHERE id = $1`,
		id, displayName)
	return err
}

func (s *DB) ReplaceGroupMembers(ctx context.Context, groupID uuid.UUID, memberIDs []uuid.UUID) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE group_id = $1`, groupID); err != nil {
		_ = tx.Rollback()
		return err
	}
	for _, uid := range memberIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			groupID, uid); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *DB) AddGroupMember(ctx context.Context, groupID, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		groupID, userID)
	return err
}

func (s *DB) RemoveGroupMember(ctx context.Context, groupID, userID uuid.UUID) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM scim_group_members WHERE group_id = $1 AND user_id = $2`,
		groupID, userID)
	return err
}

func (s *DB) DeleteGroup(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM scim_groups WHERE id = $1`, id)
	return err
}

func (s *DB) groupMembers(ctx context.Context, groupID uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id FROM scim_group_members WHERE group_id = $1 ORDER BY user_id`, groupID)
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
