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

// ── aws_accounts ──────────────────────────────────────────────────────────────

const awsAccountCols = `id, account_id, alias, oidc_provider_arn, created_at, updated_at`

func scanAWSAccount(row interface{ Scan(...any) error }) (*model.AWSAccount, error) {
	a := &model.AWSAccount{}
	err := row.Scan(&a.ID, &a.AccountID, &a.Alias, &a.OIDCProviderARN, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *DB) CreateAWSAccount(ctx context.Context, a *model.AWSAccount) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO aws_accounts (id, account_id, alias, oidc_provider_arn)
		VALUES ($1, $2, $3, $4)
		RETURNING `+awsAccountCols,
		a.ID, a.AccountID, a.Alias, a.OIDCProviderARN)
	got, err := scanAWSAccount(row)
	if isUnique(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	*a = *got
	return nil
}

func (s *DB) GetAWSAccount(ctx context.Context, id uuid.UUID) (*model.AWSAccount, error) {
	return scanAWSAccount(s.db.QueryRowContext(ctx,
		`SELECT `+awsAccountCols+` FROM aws_accounts WHERE id = $1`, id))
}

func (s *DB) ListAWSAccounts(ctx context.Context) ([]*model.AWSAccount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+awsAccountCols+` FROM aws_accounts ORDER BY account_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AWSAccount
	for rows.Next() {
		a, err := scanAWSAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *DB) UpdateAWSAccount(ctx context.Context, a *model.AWSAccount) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE aws_accounts
		   SET account_id = $2, alias = $3, oidc_provider_arn = $4, updated_at = NOW()
		 WHERE id = $1`,
		a.ID, a.AccountID, a.Alias, a.OIDCProviderARN)
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

func (s *DB) DeleteAWSAccount(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM aws_accounts WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── aws_roles ─────────────────────────────────────────────────────────────────

const awsRoleCols = `id, account_id, role_arn, slug, display_name, require_step_up_mfa, max_session_duration_sec, created_at, updated_at`

func scanAWSRole(row interface{ Scan(...any) error }) (*model.AWSRole, error) {
	r := &model.AWSRole{}
	err := row.Scan(&r.ID, &r.AccountID, &r.RoleARN, &r.Slug, &r.DisplayName,
		&r.RequireStepUpMFA, &r.MaxSessionDurationSec, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *DB) CreateAWSRole(ctx context.Context, r *model.AWSRole) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	if r.MaxSessionDurationSec == 0 {
		r.MaxSessionDurationSec = 3600
	}
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO aws_roles (id, account_id, role_arn, slug, display_name, require_step_up_mfa, max_session_duration_sec)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+awsRoleCols,
		r.ID, r.AccountID, r.RoleARN, r.Slug, r.DisplayName, r.RequireStepUpMFA, r.MaxSessionDurationSec)
	got, err := scanAWSRole(row)
	if isUnique(err) {
		return store.ErrConflict
	}
	if err != nil {
		return err
	}
	*r = *got
	return nil
}

func (s *DB) GetAWSRole(ctx context.Context, id uuid.UUID) (*model.AWSRole, error) {
	return scanAWSRole(s.db.QueryRowContext(ctx,
		`SELECT `+awsRoleCols+` FROM aws_roles WHERE id = $1`, id))
}

func (s *DB) ListAWSRoles(ctx context.Context) ([]*model.AWSRole, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+awsRoleCols+` FROM aws_roles ORDER BY display_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AWSRole
	for rows.Next() {
		r, err := scanAWSRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *DB) UpdateAWSRole(ctx context.Context, r *model.AWSRole) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE aws_roles
		   SET role_arn = $2, slug = $3, display_name = $4,
		       require_step_up_mfa = $5, max_session_duration_sec = $6,
		       updated_at = NOW()
		 WHERE id = $1`,
		r.ID, r.RoleARN, r.Slug, r.DisplayName, r.RequireStepUpMFA, r.MaxSessionDurationSec)
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

func (s *DB) DeleteAWSRole(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM aws_roles WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── aws_role_assignments ──────────────────────────────────────────────────────

func (s *DB) CreateAWSRoleAssignment(ctx context.Context, a *model.AWSRoleAssignment) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO aws_role_assignments (id, group_id, role_id)
		VALUES ($1, $2, $3)
		RETURNING id, group_id, role_id, created_at`,
		a.ID, a.GroupID, a.RoleID)
	err := row.Scan(&a.ID, &a.GroupID, &a.RoleID, &a.CreatedAt)
	if isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) ListAWSRoleAssignments(ctx context.Context) ([]*model.AWSRoleAssignment, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, group_id, role_id, created_at FROM aws_role_assignments ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AWSRoleAssignment
	for rows.Next() {
		a := &model.AWSRoleAssignment{}
		if err := rows.Scan(&a.ID, &a.GroupID, &a.RoleID, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ListAWSRolesForUser joins scim_group_members → aws_role_assignments → aws_roles
// for one user, returning distinct roles. Used by the portal tile page so a
// user only sees roles their group memberships actually grant.
func (s *DB) ListAWSRolesForUser(ctx context.Context, userID uuid.UUID) ([]*model.AWSRole, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT r.id, r.account_id, r.role_arn, r.slug, r.display_name,
		                r.require_step_up_mfa, r.max_session_duration_sec, r.created_at, r.updated_at
		  FROM aws_roles r
		  JOIN aws_role_assignments a ON a.role_id = r.id
		  JOIN scim_group_members m   ON m.group_id = a.group_id
		 WHERE m.user_id = $1
		 ORDER BY r.display_name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AWSRole
	for rows.Next() {
		r, err := scanAWSRole(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *DB) DeleteAWSRoleAssignment(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM aws_role_assignments WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ── aws_revoked_users ─────────────────────────────────────────────────────────

// AddAWSRevokedUser is idempotent: re-adding an already-revoked (role,user)
// pair updates revoked_at to "now" so the reaper window starts fresh. Useful
// when a user is re-deactivated after being reactivated mid-window.
func (s *DB) AddAWSRevokedUser(ctx context.Context, roleID uuid.UUID, subUUID string) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO aws_revoked_users (role_id, sub_uuid, revoked_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (role_id, sub_uuid) DO UPDATE SET revoked_at = EXCLUDED.revoked_at`,
		roleID, subUUID)
	return err
}

func (s *DB) ListAWSRevokedUsers(ctx context.Context, roleID uuid.UUID) ([]*model.AWSRevokedUser, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role_id, sub_uuid, revoked_at FROM aws_revoked_users WHERE role_id = $1 ORDER BY revoked_at`,
		roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AWSRevokedUser
	for rows.Next() {
		v := &model.AWSRevokedUser{}
		if err := rows.Scan(&v.RoleID, &v.SubUUID, &v.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *DB) ListAWSRevokedUsersOlderThan(ctx context.Context, cutoff time.Time) ([]*model.AWSRevokedUser, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT role_id, sub_uuid, revoked_at FROM aws_revoked_users WHERE revoked_at < $1 ORDER BY revoked_at`,
		cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.AWSRevokedUser
	for rows.Next() {
		v := &model.AWSRevokedUser{}
		if err := rows.Scan(&v.RoleID, &v.SubUUID, &v.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *DB) DeleteAWSRevokedUser(ctx context.Context, roleID uuid.UUID, subUUID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM aws_revoked_users WHERE role_id = $1 AND sub_uuid = $2`,
		roleID, subUUID)
	return err
}
