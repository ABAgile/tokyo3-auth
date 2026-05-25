package postgres

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/abagile/tokyo3-auth/internal/store"
	"github.com/google/uuid"
)

const deviceGrantCols = `id, device_code_hash, user_code_hash, client_id, scopes, status, user_id, mfa_verified, mfa_verified_at, approver_ip, interval_sec, last_polled_at, created_at, expires_at`

func scanDeviceGrant(row interface{ Scan(...any) error }) (*model.DeviceGrant, error) {
	g := &model.DeviceGrant{}
	var nullUser sql.Null[uuid.UUID]
	var nullMFAAt sql.NullTime
	var nullPolled sql.NullTime
	var scopes string
	err := row.Scan(
		&g.ID, &g.DeviceCodeHash, &g.UserCodeHash, &g.ClientID,
		&scopes, &g.Status, &nullUser,
		&g.MFAVerified, &nullMFAAt, &g.ApproverIP,
		&g.IntervalSec, &nullPolled, &g.CreatedAt, &g.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if nullUser.Valid {
		u := nullUser.V
		g.UserID = &u
	}
	if nullMFAAt.Valid {
		t := nullMFAAt.Time
		g.MFAVerifiedAt = &t
	}
	if nullPolled.Valid {
		t := nullPolled.Time
		g.LastPolledAt = &t
	}
	if scopes != "" {
		g.Scopes = strings.Fields(scopes)
	}
	return g, nil
}

func (s *DB) CreateDeviceGrant(ctx context.Context, g *model.DeviceGrant) error {
	if g.ID == uuid.Nil {
		g.ID = uuid.New()
	}
	if g.IntervalSec == 0 {
		g.IntervalSec = 5
	}
	if g.Status == "" {
		g.Status = model.DeviceGrantStatusPending
	}
	scopes := strings.Join(g.Scopes, " ")
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO device_grants (id, device_code_hash, user_code_hash, client_id, scopes, status, interval_sec, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		g.ID, g.DeviceCodeHash, g.UserCodeHash, g.ClientID, scopes, g.Status, g.IntervalSec, g.ExpiresAt)
	if isUnique(err) {
		return store.ErrConflict
	}
	return err
}

func (s *DB) GetDeviceGrantByDeviceCodeHash(ctx context.Context, hash string) (*model.DeviceGrant, error) {
	return scanDeviceGrant(s.db.QueryRowContext(ctx,
		`SELECT `+deviceGrantCols+` FROM device_grants WHERE device_code_hash = $1`, hash))
}

func (s *DB) GetDeviceGrantByUserCodeHash(ctx context.Context, hash string) (*model.DeviceGrant, error) {
	return scanDeviceGrant(s.db.QueryRowContext(ctx,
		`SELECT `+deviceGrantCols+` FROM device_grants WHERE user_code_hash = $1`, hash))
}

func (s *DB) MarkDeviceGrantApproved(ctx context.Context, id, userID uuid.UUID, mfaVerified bool, mfaVerifiedAt *time.Time, approverIP string) error {
	var mfaAt any
	if mfaVerifiedAt != nil {
		mfaAt = *mfaVerifiedAt
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE device_grants
		   SET status = $2, user_id = $3, mfa_verified = $4, mfa_verified_at = $5, approver_ip = $6
		 WHERE id = $1 AND status = $7`,
		id, model.DeviceGrantStatusApproved, userID, mfaVerified, mfaAt, approverIP,
		model.DeviceGrantStatusPending)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) MarkDeviceGrantDenied(ctx context.Context, id uuid.UUID, approverIP string) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE device_grants
		   SET status = $2, approver_ip = $3
		 WHERE id = $1 AND status = $4`,
		id, model.DeviceGrantStatusDenied, approverIP, model.DeviceGrantStatusPending)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) MarkDeviceGrantRedeemed(ctx context.Context, id uuid.UUID) error {
	res, err := s.db.ExecContext(ctx, `
		UPDATE device_grants
		   SET status = $2
		 WHERE id = $1 AND status = $3`,
		id, model.DeviceGrantStatusRedeemed, model.DeviceGrantStatusApproved)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *DB) UpdateDeviceGrantPoll(ctx context.Context, id uuid.UUID, now time.Time, intervalSec int) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE device_grants SET last_polled_at = $2, interval_sec = $3 WHERE id = $1`,
		id, now, intervalSec)
	return err
}

func (s *DB) DeleteExpiredDeviceGrants(ctx context.Context) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM device_grants WHERE expires_at < NOW()`)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}
