package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

func (s *DB) CreateAuditLog(ctx context.Context, log *model.AuditLog) error {
	meta, err := json.Marshal(log.Metadata)
	if err != nil || len(meta) == 0 {
		meta = []byte("{}")
	}
	// Pass *uuid.UUID through database/sql by dereferencing to driver-friendly
	// values (uuid.UUID for set, nil for absent) — sqlite stores them as TEXT.
	var userID, clientID any
	if log.UserID != nil {
		userID = *log.UserID
	}
	if log.ClientID != nil {
		clientID = *log.ClientID
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO audit_logs (id, user_id, client_id, action, ip, user_agent, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		log.ID, userID, clientID, log.Action, log.IP, log.UserAgent, string(meta))
	return err
}

func (s *DB) ListAuditLogs(ctx context.Context, limit, offset int) ([]*model.AuditLog, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, client_id, action, ip, user_agent, metadata, created_at
		 FROM audit_logs ORDER BY created_at DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []*model.AuditLog
	for rows.Next() {
		l := &model.AuditLog{}
		var (
			userID, clientID sql.NullString
			meta             []byte
		)
		if err := rows.Scan(&l.ID, &userID, &clientID, &l.Action, &l.IP, &l.UserAgent, &meta, &l.CreatedAt); err != nil {
			return nil, err
		}
		if userID.Valid {
			if u, err := uuid.Parse(userID.String); err == nil {
				l.UserID = &u
			}
		}
		if clientID.Valid {
			if c, err := uuid.Parse(clientID.String); err == nil {
				l.ClientID = &c
			}
		}
		_ = json.Unmarshal(meta, &l.Metadata)
		logs = append(logs, l)
	}
	return logs, rows.Err()
}
