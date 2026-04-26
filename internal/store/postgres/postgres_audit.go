package postgres

import (
	"context"
	"encoding/json"

	"github.com/abagile/tokyo3-auth/internal/model"
)

func (s *DB) CreateAuditLog(ctx context.Context, log *model.AuditLog) error {
	meta, err := json.Marshal(log.Metadata)
	if err != nil {
		meta = []byte("{}")
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (id, user_id, client_id, action, ip, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		log.ID, log.UserID, log.ClientID, log.Action, log.IP, log.UserAgent, meta)
	return err
}

func (s *DB) ListAuditLogs(ctx context.Context, limit, offset int) ([]*model.AuditLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, client_id, action, ip, user_agent, metadata, created_at
		 FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []*model.AuditLog
	for rows.Next() {
		l := &model.AuditLog{}
		var meta []byte
		if err := rows.Scan(&l.ID, &l.UserID, &l.ClientID, &l.Action, &l.IP, &l.UserAgent, &meta, &l.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(meta, &l.Metadata)
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
