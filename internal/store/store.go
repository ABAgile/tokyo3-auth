package store

import (
	"context"
	"errors"
	"time"

	"github.com/abagile/tokyo3-auth/internal/model"
	"github.com/google/uuid"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store interface {
	UserStore
	ClientStore
	GrantStore
	SessionStore
	MFAStore
	SCIMTokenStore
	GroupStore
	SigningKeyStore
	AuditStore
	ExternalIDStore
}

type UserStore interface {
	CreateUser(ctx context.Context, email, passwordHash, name string) (*model.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
	ListUsers(ctx context.Context) ([]*model.User, error)
	UpdateUser(ctx context.Context, id uuid.UUID, name string, active bool) error
	UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error
	UpdateUserMFAEnabled(ctx context.Context, id uuid.UUID, enabled bool) error
	UpdateUserFailedAttempts(ctx context.Context, id uuid.UUID, count int, lockedUntil *time.Time) error
	SetUserActive(ctx context.Context, id uuid.UUID, active bool) error
	SetUserSCIMExternalID(ctx context.Context, id uuid.UUID, externalID string) error
	SetUserAdmin(ctx context.Context, id uuid.UUID, isAdmin bool) error
	DeleteUser(ctx context.Context, id uuid.UUID) error
}

type ClientStore interface {
	CreateClient(ctx context.Context, clientID, clientSecretHash, name string, redirectURIs, scopes []string, public bool) (*model.Client, error)
	GetClientByID(ctx context.Context, id uuid.UUID) (*model.Client, error)
	GetClientByClientID(ctx context.Context, clientID string) (*model.Client, error)
	ListClients(ctx context.Context) ([]*model.Client, error)
	UpdateClientSecret(ctx context.Context, id uuid.UUID, secretHash string) error
	DeleteClient(ctx context.Context, id uuid.UUID) error
}

type GrantStore interface {
	CreateGrant(ctx context.Context, g *model.Grant) error
	GetGrantByCodeHash(ctx context.Context, codeHash string) (*model.Grant, error)
	MarkGrantUsed(ctx context.Context, id uuid.UUID) error
	DeleteExpiredGrants(ctx context.Context) error
}

type SessionStore interface {
	CreateSession(ctx context.Context, s *model.Session) error
	GetSessionByAccessTokenHash(ctx context.Context, hash string) (*model.Session, error)
	GetSessionByRefreshTokenHash(ctx context.Context, hash string) (*model.Session, error)
	UpdateSessionActivity(ctx context.Context, id uuid.UUID, lastActivity time.Time) error
	RotateRefreshToken(ctx context.Context, id uuid.UUID, newRefreshHash string, newExpiry time.Time) error
	DeleteSession(ctx context.Context, id uuid.UUID) error
	DeleteSessionsByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteExpiredSessions(ctx context.Context) error
}

type MFAStore interface {
	CreateTOTPCredential(ctx context.Context, c *model.TOTPCredential) error
	GetTOTPByUserID(ctx context.Context, userID uuid.UUID) (*model.TOTPCredential, error)
	EnableTOTP(ctx context.Context, id uuid.UUID) error
	DeleteTOTP(ctx context.Context, userID uuid.UUID) error

	CreateWebAuthnCredential(ctx context.Context, c *model.WebAuthnCredential) error
	ListWebAuthnCredentials(ctx context.Context, userID uuid.UUID) ([]*model.WebAuthnCredential, error)
	GetWebAuthnCredentialByCredentialID(ctx context.Context, credID []byte) (*model.WebAuthnCredential, error)
	UpdateWebAuthnSignCount(ctx context.Context, id uuid.UUID, signCount uint32, lastUsed time.Time) error
	DeleteWebAuthnCredential(ctx context.Context, id uuid.UUID, userID uuid.UUID) error

	CreateWebAuthnSession(ctx context.Context, userID uuid.UUID, data []byte, purpose string) (uuid.UUID, error)
	GetWebAuthnSession(ctx context.Context, id uuid.UUID, userID uuid.UUID, purpose string) ([]byte, error)
	DeleteWebAuthnSession(ctx context.Context, id uuid.UUID) error
}

type SCIMTokenStore interface {
	CreateSCIMToken(ctx context.Context, t *model.SCIMToken) error
	GetSCIMTokenByHash(ctx context.Context, hash string) (*model.SCIMToken, error)
	ListSCIMTokens(ctx context.Context) ([]*model.SCIMToken, error)
	DeleteSCIMToken(ctx context.Context, id uuid.UUID) error
}

type GroupStore interface {
	CreateGroup(ctx context.Context, displayName string) (*model.SCIMGroup, error)
	GetGroupByID(ctx context.Context, id uuid.UUID) (*model.SCIMGroup, error)
	ListGroups(ctx context.Context) ([]*model.SCIMGroup, error)
	UpdateGroup(ctx context.Context, id uuid.UUID, displayName string) error
	ReplaceGroupMembers(ctx context.Context, groupID uuid.UUID, memberIDs []uuid.UUID) error
	AddGroupMember(ctx context.Context, groupID, userID uuid.UUID) error
	RemoveGroupMember(ctx context.Context, groupID, userID uuid.UUID) error
	DeleteGroup(ctx context.Context, id uuid.UUID) error
}

type SigningKeyStore interface {
	CreateSigningKey(ctx context.Context, k *model.SigningKey) error
	GetActiveSigningKey(ctx context.Context) (*model.SigningKey, error)
	ListActiveSigningKeys(ctx context.Context) ([]*model.SigningKey, error)
	DeactivateSigningKey(ctx context.Context, id uuid.UUID) error
}

type AuditStore interface {
	CreateAuditLog(ctx context.Context, log *model.AuditLog) error
	ListAuditLogs(ctx context.Context, limit, offset int) ([]*model.AuditLog, error)
}

// ExternalIDStore caches each user's identity in downstream provisioning targets
// (vault, AWS IAM, etc.). It is a best-effort cache: outbound provisioners write
// the downstream UUID on first create and read it back to avoid a filter lookup
// per update. Callers MUST be prepared for ErrNotFound on Get and treat it as a
// cache miss (re-resolve via the downstream's filter, then SetExternalID).
type ExternalIDStore interface {
	GetExternalID(ctx context.Context, provider string, userID uuid.UUID) (string, error)
	SetExternalID(ctx context.Context, provider string, userID uuid.UUID, externalID string) error
	DeleteExternalID(ctx context.Context, provider string, userID uuid.UUID) error
}
